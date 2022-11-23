package tap

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kubeshark/kubeshark/agent/pkg/models"

	"github.com/kubeshark/kubeshark/agent/pkg/app"

	"github.com/gorilla/websocket"
	"github.com/kubeshark/kubeshark/logger"
	"github.com/kubeshark/kubeshark/shared"
	tap "github.com/kubeshark/worker"
	tapApi "github.com/kubeshark/worker/api"
	"github.com/kubeshark/worker/dbgctl"
	"github.com/op/go-logging"
)

var apiServerAddress = flag.String("api-server-address", "", "Address of kubeshark API server")
var namespace = flag.String("namespace", "", "Resolve IPs if they belong to resources in this namespace (default is all)")
var harsReaderMode = flag.Bool("hars-read", false, "Run in hars-read mode")
var harsDir = flag.String("hars-dir", "", "Directory to read hars from")
var profiler = flag.Bool("profiler", false, "Run pprof server")

const (
	socketConnectionRetries    = 30
	socketConnectionRetryDelay = time.Second * 2
	socketHandshakeTimeout     = time.Second * 2
)

func main() {
	logLevel := determineLogLevel()
	logger.InitLoggerStd(logLevel)
	flag.Parse()

	app.LoadExtensions()

	runInTapperMode()

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt)
	<-signalChan

	logger.Log.Info("Exiting")
}

func runInTapperMode() {
	logger.Log.Infof("Starting tapper, websocket address: %s", *apiServerAddress)
	if *apiServerAddress == "" {
		panic("API server address must be provided with --api-server-address when using --tap")
	}

	hostMode := os.Getenv(shared.HostModeEnvVar) == "1"
	tapOpts := &tap.TapOpts{
		HostMode: hostMode,
	}

	filteredOutputItemsChannel := make(chan *tapApi.OutputChannelItem)

	filteringOptions := getTrafficFilteringOptions()
	tap.StartPassiveTapper(tapOpts, filteredOutputItemsChannel, app.Extensions, filteringOptions)
	socketConnection, err := dialSocketWithRetry(*apiServerAddress, socketConnectionRetries, socketConnectionRetryDelay)
	if err != nil {
		panic(fmt.Sprintf("Error connecting to socket server at %s %v", *apiServerAddress, err))
	}
	logger.Log.Infof("Connected successfully to websocket %s", *apiServerAddress)

	go pipeTapChannelToSocket(socketConnection, filteredOutputItemsChannel)
}

func getTrafficFilteringOptions() *tapApi.TrafficFilteringOptions {
	filteringOptionsJson := os.Getenv(shared.KubesharkFilteringOptionsEnvVar)
	if filteringOptionsJson == "" {
		return &tapApi.TrafficFilteringOptions{
			IgnoredUserAgents: []string{},
		}
	}
	var filteringOptions tapApi.TrafficFilteringOptions
	err := json.Unmarshal([]byte(filteringOptionsJson), &filteringOptions)
	if err != nil {
		panic(fmt.Sprintf("env var %s's value of %s is invalid! json must match the api.TrafficFilteringOptions struct %v", shared.KubesharkFilteringOptionsEnvVar, filteringOptionsJson, err))
	}

	return &filteringOptions
}

func pipeTapChannelToSocket(connection *websocket.Conn, messageDataChannel <-chan *tapApi.OutputChannelItem) {
	if connection == nil {
		panic("Websocket connection is nil")
	}

	if messageDataChannel == nil {
		panic("Channel of captured messages is nil")
	}

	for messageData := range messageDataChannel {
		marshaledData, err := models.CreateWebsocketTappedEntryMessage(messageData)
		if err != nil {
			logger.Log.Errorf("error converting message to json %v, err: %s, (%v,%+v)", messageData, err, err, err)
			continue
		}

		if dbgctl.KubesharkTapperDisableSending {
			continue
		}

		// NOTE: This is where the `*tapApi.OutputChannelItem` leaves the code
		// and goes into the intermediate WebSocket.
		err = connection.WriteMessage(websocket.TextMessage, marshaledData)
		if err != nil {
			logger.Log.Errorf("error sending message through socket server %v, err: %s, (%v,%+v)", messageData, err, err, err)
			if errors.Is(err, syscall.EPIPE) {
				logger.Log.Warning("detected socket disconnection, reestablishing socket connection")
				connection, err = dialSocketWithRetry(*apiServerAddress, socketConnectionRetries, socketConnectionRetryDelay)
				if err != nil {
					logger.Log.Fatalf("error reestablishing socket connection: %v", err)
				} else {
					logger.Log.Info("recovered connection successfully")
				}
			}
			continue
		}
	}
}

func determineLogLevel() (logLevel logging.Level) {
	logLevel, err := logging.LogLevel(os.Getenv(shared.LogLevelEnvVar))
	if err != nil {
		logLevel = logging.INFO
	}

	return
}

func dialSocketWithRetry(socketAddress string, retryAmount int, retryDelay time.Duration) (*websocket.Conn, error) {
	var lastErr error
	dialer := &websocket.Dialer{ // we use our own dialer instead of the default due to the default's 45 sec handshake timeout, we occasionally encounter hanging socket handshakes when tapper tries to connect to api too soon
		Proxy:            http.ProxyFromEnvironment,
		HandshakeTimeout: socketHandshakeTimeout,
	}
	for i := 1; i < retryAmount; i++ {
		socketConnection, _, err := dialer.Dial(socketAddress, nil)
		if err != nil {
			lastErr = err
			if i < retryAmount {
				logger.Log.Infof("socket connection to %s failed: %v, retrying %d out of %d in %d seconds...", socketAddress, err, i, retryAmount, retryDelay/time.Second)
				time.Sleep(retryDelay)
			}
		} else {
			go handleIncomingMessageAsTapper(socketConnection)
			return socketConnection, nil
		}
	}
	return nil, lastErr
}

func handleIncomingMessageAsTapper(socketConnection *websocket.Conn) {
	for {
		if _, message, err := socketConnection.ReadMessage(); err != nil {
			logger.Log.Errorf("error reading message from socket connection, err: %s, (%v,%+v)", err, err, err)
			if errors.Is(err, syscall.EPIPE) {
				// socket has disconnected, we can safely stop this goroutine
				return
			}
		} else {
			var socketMessageBase shared.WebSocketMessageMetadata
			if err := json.Unmarshal(message, &socketMessageBase); err != nil {
				logger.Log.Errorf("Could not unmarshal websocket message %v", err)
			} else {
				switch socketMessageBase.MessageType {
				case shared.WebSocketMessageTypeTapConfig:
					var tapConfigMessage *shared.WebSocketTapConfigMessage
					if err := json.Unmarshal(message, &tapConfigMessage); err != nil {
						logger.Log.Errorf("received unknown message from socket connection: %s, err: %s, (%v,%+v)", string(message), err, err, err)
					} else {
						tap.UpdateTapTargets(tapConfigMessage.TapTargets)
					}
				case shared.WebSocketMessageTypeUpdateTappedPods:
					var tappedPodsMessage shared.WebSocketTappedPodsMessage
					if err := json.Unmarshal(message, &tappedPodsMessage); err != nil {
						logger.Log.Infof("Could not unmarshal message of message type %s %v", socketMessageBase.MessageType, err)
						return
					}
					nodeName := os.Getenv(shared.NodeNameEnvVar)
					tap.UpdateTapTargets(tappedPodsMessage.NodeToTappedPodMap[nodeName])
				default:
					logger.Log.Warningf("Received socket message of type %s for which no handlers are defined", socketMessageBase.MessageType)
				}
			}
		}
	}
}