package controllers

import (
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/kubeshark/worker/assemblers"
	"github.com/kubeshark/worker/misc"
	"github.com/kubeshark/worker/misc/wcap"
	"github.com/kubeshark/worker/pkg/api"
	"github.com/kubeshark/worker/pkg/languages/kfl"
	"github.com/kubeshark/worker/source"
	"github.com/kubeshark/worker/utils"
	"github.com/kubeshark/worker/vm"
	"github.com/rs/zerolog/log"
)

var (
	websocketUpgrader = websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
	}
)

func init() {
	websocketUpgrader.CheckOrigin = func(r *http.Request) bool { return true } // like cors for web socket
}

func WebsocketHandler(c *gin.Context, opts *misc.Opts) {
	ws, err := websocketUpgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Error().Err(err).Msg("Failed to set WebSocket upgrade:")
		return
	}
	defer ws.Close()

	shutdown := make(chan bool)
	outputChannel := make(chan *api.OutputChannelItem)

	go writeChannelToSocket(outputChannel, ws, c.Query("worker"), c.Query("node"), c.Query("q"))

	go func() {
		for {
			_, _, err := ws.ReadMessage()
			if err != nil {
				log.Info().Err(err).Msg("WebSocket read:")
				shutdown <- true
				return
			}
		}
	}()

	s, err := source.NewTcpPacketSource(misc.GetMasterPcapPath(), misc.GetMasterPcapPath(), "", "libpcap")
	if err != nil {
		log.Error().Err(err).Msg("Failed creating packet source:")
		return
	}

	sortedPackets := make(chan *wcap.SortedPacket)
	writer, err := wcap.NewWriter(c.Query("c"))
	if err != nil {
		log.Error().Err(err).Msg("Failed creating writer:")
		return
	}
	go writer.Write(sortedPackets)

	assembler := assemblers.NewTcpAssembler(
		"",
		assemblers.SortCapture,
		sortedPackets,
		outputChannel,
		assemblers.NewTcpStreamMap(),
		opts,
	)

	packets := make(chan source.TcpPacketInfo)
	go s.ReadPackets(packets, true, false, sortedPackets)
	go assembler.ProcessPackets(packets)

	<-shutdown

	s.Close()
	writer.Clean()

	log.Info().Msg("WebSocket is closed!")
}

func writeChannelToSocket(outputChannel <-chan *api.OutputChannelItem, ws *websocket.Conn, worker string, node string, query string) {
	var counter uint64
	expr, prop, err := kfl.PrepareQuery(query)
	if err != nil {
		log.Error().Err(err).Send()
		return
	}

	for item := range outputChannel {
		// TODO: The previously bad design forces us to Marshal and Unmarshal
		data, err := json.Marshal(item)
		if err != nil {
			log.Error().Err(err).Msg("Failed marshalling item:")
			continue
		}
		var finalItem *api.OutputChannelItem
		err = json.Unmarshal(data, &finalItem)
		if err != nil {
			log.Error().Err(err).Msg("Failed unmarshalling item:")
			continue
		}

		entry := utils.ItemToEntry(finalItem)
		entry.Worker = worker
		entry.Node.IP = misc.RemovePortFromWorkerHost(worker)
		entry.Node.Name = node
		entry.BuildId()

		entryMarshaled, err := json.Marshal(entry)
		if err != nil {
			log.Error().Err(err).Msg("Failed marshalling entry:")
			continue
		}

		if prop.Limit > 0 && counter >= prop.Limit {
			return
		}

		truth, record, err := kfl.Eval(expr, string(entryMarshaled))
		if err != nil {
			log.Error().Err(err).Msg("Failed applying query:")
			continue
		}

		if !truth {
			continue
		}

		var alteredEntry *api.Entry
		err = json.Unmarshal([]byte(record), &alteredEntry)
		if err != nil {
			log.Error().Err(err).Msg("Failed unmarshalling altered item:")
			continue
		}

		alteredEntry = vm.ItemQueriedHook(alteredEntry)

		baseEntry := utils.SummarizeEntry(alteredEntry)

		summary, err := json.Marshal(baseEntry)
		if err != nil {
			log.Error().Err(err).Msg("Failed marshalling summary:")
			continue
		}

		err = ws.WriteMessage(1, summary)
		if err != nil {
			log.Error().Err(err).Msg("Failed to set write message to WebSocket:")
			return
		}

		counter++
	}
}
