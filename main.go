package main

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

	"github.com/gorilla/websocket"
	"github.com/kubeshark/base/pkg/api"
	"github.com/kubeshark/base/pkg/models"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var hubWsAddress = flag.String("hub-ws-address", "ws://localhost:8898/wsWorker", "The address of the Hub WebSocket endpoint.")

const (
	HostModeEnvVar             = "HOST_MODE"
	NodeNameEnvVar             = "NODE_NAME"
	socketConnectionRetries    = 3
	socketConnectionRetryDelay = time.Second * 2
	socketHandshakeTimeout     = time.Second * 2
)

func main() {
	flag.Parse()

	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339})

	if *debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}

	loadExtensions()

	run()

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt)
	<-signalChan

	log.Info().Msg("Exiting")
}

func run() {
	log.Info().Str("addr", *hubWsAddress).Msg("Starting worker, WebSocket address:")

	hostMode := os.Getenv(HostModeEnvVar) == "1"
	opts := &Opts{
		HostMode: hostMode,
	}

	filteredOutputItemsChannel := make(chan *api.OutputChannelItem)

	filteringOptions := getTrafficFilteringOptions()
	startWorker(opts, filteredOutputItemsChannel, Extensions, filteringOptions)
	socketConnection, err := dialSocketWithRetry(*hubWsAddress, socketConnectionRetries, socketConnectionRetryDelay)
	if err != nil {
		log.Fatal().Err(err).Str("addr", *hubWsAddress).Msg("Error connecting to socket server!")
	}

	log.Info().Str("addr", *hubWsAddress).Msg("Connected successfully to the WebSocket")

	go pipeWorkerChannelToSocket(socketConnection, filteredOutputItemsChannel)
}

func getTrafficFilteringOptions() *api.TrafficFilteringOptions {
	return &api.TrafficFilteringOptions{
		IgnoredUserAgents: []string{},
	}
}

func pipeWorkerChannelToSocket(connection *websocket.Conn, messageDataChannel <-chan *api.OutputChannelItem) {
	for messageData := range messageDataChannel {
		marshaledData, err := models.CreateWebsocketWorkerEntryMessage(messageData)
		if err != nil {
			log.Error().Err(err).Interface("message-data", messageData).Msg("While converting message to JSON!")
			continue
		}

		// NOTE: This is where the `*api.OutputChannelItem` leaves the code
		// and goes into the intermediate WebSocket.
		err = connection.WriteMessage(websocket.TextMessage, marshaledData)
		if err != nil {
			log.Error().Err(err).Interface("message-data", messageData).Msg("While sending message through socket server!")
			if errors.Is(err, syscall.EPIPE) {
				log.Warn().Msg("Detected socket disconnection, reestablishing socket connection...")
				connection, err = dialSocketWithRetry(*hubWsAddress, socketConnectionRetries, socketConnectionRetryDelay)
				if err != nil {
					log.Fatal().Err(err).Msg("While re-establishing socket connection!")
				} else {
					log.Info().Msg("Recovered the connection successfully.")
				}
			}
			continue
		}
	}
}

func dialSocketWithRetry(socketAddress string, retryAmount int, retryDelay time.Duration) (*websocket.Conn, error) {
	var lastErr error
	dialer := &websocket.Dialer{ // we use our own dialer instead of the default due to the default's 45 sec handshake timeout, we occasionally encounter hanging socket handshakes when Worker tries to connect to Hub too soon
		Proxy:            http.ProxyFromEnvironment,
		HandshakeTimeout: socketHandshakeTimeout,
	}
	for i := 1; i < retryAmount; i++ {
		socketConnection, _, err := dialer.Dial(socketAddress, nil)
		if err != nil {
			lastErr = err
			if i < retryAmount {
				log.Warn().Err(err).Str("addr", socketAddress).Msg(fmt.Sprintf("Socket connection attempt is failed! Retrying %d out of %d in %d seconds...", i, retryAmount, retryDelay/time.Second))
				time.Sleep(retryDelay)
			}
		} else {
			go handleIncomingMessageAsWorker(socketConnection)
			return socketConnection, nil
		}
	}
	return nil, lastErr
}

func handleIncomingMessageAsWorker(socketConnection *websocket.Conn) {
	for {
		if _, message, err := socketConnection.ReadMessage(); err != nil {
			log.Error().Err(err).Msg("While reading message from the socket connection!")
			if errors.Is(err, syscall.EPIPE) {
				// socket has disconnected, we can safely stop this goroutine
				return
			}
		} else {
			var socketMessageBase models.WebSocketMessageMetadata
			if err := json.Unmarshal(message, &socketMessageBase); err != nil {
				log.Error().Err(err).Msg("Couldn't unmarshal socket message!")
			} else {
				switch socketMessageBase.MessageType {
				case models.WebSocketMessageTypeWorkerConfig:
					var configMessage *models.WebSocketWorkerConfigMessage
					if err := json.Unmarshal(message, &configMessage); err != nil {
						log.Error().Err(err).Str("msg", string(message)).Msg("Received unknown message from the socket connection:")
					} else {
						UpdateTargets(configMessage.TargettedPods)
					}
				case models.WebSocketMessageTypeUpdateTargettedPods:
					var targettedPodsMessage models.WebSocketTargettedPodsMessage
					if err := json.Unmarshal(message, &targettedPodsMessage); err != nil {
						log.Error().Err(err).Str("msg-type", string(socketMessageBase.MessageType)).Msg("Couldn't unmarshal message of message type:")
						return
					}
					nodeName := os.Getenv(NodeNameEnvVar)
					UpdateTargets(targettedPodsMessage.NodeToTargettedPodsMap[nodeName])
				default:
					log.Error().Str("msg-type", string(socketMessageBase.MessageType)).Msg("Received a socket message type which no handlers are defined for!")
				}
			}
		}
	}
}
