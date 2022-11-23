package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"github.com/kubeshark/worker/api"
	"github.com/kubeshark/worker/dbgctl"
)

var apiServerAddress = flag.String("api-server-address", "", "Address of kubeshark API server")
var namespace = flag.String("namespace", "", "Resolve IPs if they belong to resources in this namespace (default is all)")
var harsReaderMode = flag.Bool("hars-read", false, "Run in hars-read mode")
var harsDir = flag.String("hars-dir", "", "Directory to read hars from")
var profiler = flag.Bool("profiler", false, "Run pprof server")

const (
	HostModeEnvVar             = "HOST_MODE"
	NodeNameEnvVar             = "NODE_NAME"
	socketConnectionRetries    = 3
	socketConnectionRetryDelay = time.Second * 2
	socketHandshakeTimeout     = time.Second * 2
)

func main() {
	flag.Parse()

	loadExtensions()

	runInTapperMode()

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt)
	<-signalChan

	log.Print("Exiting")
}

func runInTapperMode() {
	log.Printf("Starting tapper, websocket address: %s", *apiServerAddress)
	if *apiServerAddress == "" {
		panic("API server address must be provided with --api-server-address when using --tap")
	}

	hostMode := os.Getenv(HostModeEnvVar) == "1"
	tapOpts := &TapOpts{
		HostMode: hostMode,
	}

	filteredOutputItemsChannel := make(chan *api.OutputChannelItem)

	filteringOptions := getTrafficFilteringOptions()
	StartPassiveTapper(tapOpts, filteredOutputItemsChannel, Extensions, filteringOptions)
	socketConnection, err := dialSocketWithRetry(*apiServerAddress, socketConnectionRetries, socketConnectionRetryDelay)
	if err != nil {
		panic(fmt.Sprintf("Error connecting to socket server at %s %v", *apiServerAddress, err))
	}
	log.Printf("Connected successfully to websocket %s", *apiServerAddress)

	go pipeTapChannelToSocket(socketConnection, filteredOutputItemsChannel)
}

func getTrafficFilteringOptions() *api.TrafficFilteringOptions {
	return &api.TrafficFilteringOptions{
		IgnoredUserAgents: []string{},
	}
}

func pipeTapChannelToSocket(connection *websocket.Conn, messageDataChannel <-chan *api.OutputChannelItem) {
	if connection == nil {
		panic("Websocket connection is nil")
	}

	if messageDataChannel == nil {
		panic("Channel of captured messages is nil")
	}

	for messageData := range messageDataChannel {
		marshaledData, err := CreateWebsocketTappedEntryMessage(messageData)
		if err != nil {
			log.Printf("error converting message to json %v, err: %s, (%v,%+v)", messageData, err, err, err)
			continue
		}

		if dbgctl.KubesharkTapperDisableSending {
			continue
		}

		// NOTE: This is where the `*api.OutputChannelItem` leaves the code
		// and goes into the intermediate WebSocket.
		err = connection.WriteMessage(websocket.TextMessage, marshaledData)
		if err != nil {
			log.Printf("error sending message through socket server %v, err: %s, (%v,%+v)", messageData, err, err, err)
			if errors.Is(err, syscall.EPIPE) {
				log.Printf("detected socket disconnection, reestablishing socket connection")
				connection, err = dialSocketWithRetry(*apiServerAddress, socketConnectionRetries, socketConnectionRetryDelay)
				if err != nil {
					log.Fatalf("error reestablishing socket connection: %v", err)
				} else {
					log.Print("recovered connection successfully")
				}
			}
			continue
		}
	}
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
				log.Printf("socket connection to %s failed: %v, retrying %d out of %d in %d seconds...", socketAddress, err, i, retryAmount, retryDelay/time.Second)
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
			log.Printf("error reading message from socket connection, err: %s, (%v,%+v)", err, err, err)
			if errors.Is(err, syscall.EPIPE) {
				// socket has disconnected, we can safely stop this goroutine
				return
			}
		} else {
			var socketMessageBase WebSocketMessageMetadata
			if err := json.Unmarshal(message, &socketMessageBase); err != nil {
				log.Printf("Could not unmarshal websocket message %v", err)
			} else {
				switch socketMessageBase.MessageType {
				case WebSocketMessageTypeTapConfig:
					var tapConfigMessage *WebSocketTapConfigMessage
					if err := json.Unmarshal(message, &tapConfigMessage); err != nil {
						log.Printf("received unknown message from socket connection: %s, err: %s, (%v,%+v)", string(message), err, err, err)
					} else {
						UpdateTapTargets(tapConfigMessage.TapTargets)
					}
				case WebSocketMessageTypeUpdateTappedPods:
					var tappedPodsMessage WebSocketTappedPodsMessage
					if err := json.Unmarshal(message, &tappedPodsMessage); err != nil {
						log.Printf("Could not unmarshal message of message type %s %v", socketMessageBase.MessageType, err)
						return
					}
					nodeName := os.Getenv(NodeNameEnvVar)
					UpdateTapTargets(tappedPodsMessage.NodeToTappedPodMap[nodeName])
				default:
					log.Printf("Received socket message of type %s for which no handlers are defined", socketMessageBase.MessageType)
				}
			}
		}
	}
}
