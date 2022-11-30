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
	"github.com/kubeshark/base/pkg/api"
	"github.com/kubeshark/base/pkg/models"
)

var hubWsAddress = flag.String("hub-ws-address", "ws://localhost:8899/wsWorker", "The address of the Hub WebSocket endpoint.")

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

	run()

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt)
	<-signalChan

	log.Print("Exiting")
}

func run() {
	log.Printf("Starting worker, WebSocket address: %s", *hubWsAddress)

	hostMode := os.Getenv(HostModeEnvVar) == "1"
	opts := &Opts{
		HostMode: hostMode,
	}

	filteredOutputItemsChannel := make(chan *api.OutputChannelItem)

	filteringOptions := getTrafficFilteringOptions()
	startWorker(opts, filteredOutputItemsChannel, Extensions, filteringOptions)
	socketConnection, err := dialSocketWithRetry(*hubWsAddress, socketConnectionRetries, socketConnectionRetryDelay)
	if err != nil {
		panic(fmt.Sprintf("Error connecting to socket server at %s %v", *hubWsAddress, err))
	}
	log.Printf("Connected successfully to websocket %s", *hubWsAddress)

	go pipeWorkerChannelToSocket(socketConnection, filteredOutputItemsChannel)
}

func getTrafficFilteringOptions() *api.TrafficFilteringOptions {
	return &api.TrafficFilteringOptions{
		IgnoredUserAgents: []string{},
	}
}

func pipeWorkerChannelToSocket(connection *websocket.Conn, messageDataChannel <-chan *api.OutputChannelItem) {
	if connection == nil {
		panic("Websocket connection is nil")
	}

	if messageDataChannel == nil {
		panic("Channel of captured messages is nil")
	}

	for messageData := range messageDataChannel {
		marshaledData, err := models.CreateWebsocketWorkerEntryMessage(messageData)
		if err != nil {
			log.Printf("error converting message to json %v, err: %s, (%v,%+v)", messageData, err, err, err)
			continue
		}

		// NOTE: This is where the `*api.OutputChannelItem` leaves the code
		// and goes into the intermediate WebSocket.
		err = connection.WriteMessage(websocket.TextMessage, marshaledData)
		if err != nil {
			log.Printf("error sending message through socket server %v, err: %s, (%v,%+v)", messageData, err, err, err)
			if errors.Is(err, syscall.EPIPE) {
				log.Printf("detected socket disconnection, reestablishing socket connection")
				connection, err = dialSocketWithRetry(*hubWsAddress, socketConnectionRetries, socketConnectionRetryDelay)
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
	dialer := &websocket.Dialer{ // we use our own dialer instead of the default due to the default's 45 sec handshake timeout, we occasionally encounter hanging socket handshakes when Worker tries to connect to Hub too soon
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
			go handleIncomingMessageAsWorker(socketConnection)
			return socketConnection, nil
		}
	}
	return nil, lastErr
}

func handleIncomingMessageAsWorker(socketConnection *websocket.Conn) {
	for {
		if _, message, err := socketConnection.ReadMessage(); err != nil {
			log.Printf("error reading message from socket connection, err: %s, (%v,%+v)", err, err, err)
			if errors.Is(err, syscall.EPIPE) {
				// socket has disconnected, we can safely stop this goroutine
				return
			}
		} else {
			var socketMessageBase models.WebSocketMessageMetadata
			if err := json.Unmarshal(message, &socketMessageBase); err != nil {
				log.Printf("Could not unmarshal websocket message %v", err)
			} else {
				switch socketMessageBase.MessageType {
				case models.WebSocketMessageTypeWorkerConfig:
					var configMessage *models.WebSocketWorkerConfigMessage
					if err := json.Unmarshal(message, &configMessage); err != nil {
						log.Printf("received unknown message from socket connection: %s, err: %s, (%v,%+v)", string(message), err, err, err)
					} else {
						UpdateTargets(configMessage.TargettedPods)
					}
				case models.WebSocketMessageTypeUpdateTargettedPods:
					var targettedPodsMessage models.WebSocketTargettedPodsMessage
					if err := json.Unmarshal(message, &targettedPodsMessage); err != nil {
						log.Printf("Could not unmarshal message of message type %s %v", socketMessageBase.MessageType, err)
						return
					}
					nodeName := os.Getenv(NodeNameEnvVar)
					UpdateTargets(targettedPodsMessage.NodeToTargettedPodsMap[nodeName])
				default:
					log.Printf("Received socket message of type %s for which no handlers are defined", socketMessageBase.MessageType)
				}
			}
		}
	}
}
