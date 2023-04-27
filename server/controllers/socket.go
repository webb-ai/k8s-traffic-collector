package controllers

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/kubeshark/worker/assemblers"
	"github.com/kubeshark/worker/misc"
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

	pcapFiles, err := os.ReadDir(misc.GetPcapsDir())
	if err != nil {
		log.Error().Err(err).Msg("Failed get the list of PCAP files!")
	}

	var done bool
	shutdown := make(chan bool)
	outputChannel := make(chan *api.OutputChannelItem)
	var sources []*source.TcpPacketSource
	var assemblerSlice []*assemblers.TcpAssembler

	go writeChannelToSocket(outputChannel, ws, c.Query("worker"), c.Query("node"), c.Query("q"), shutdown)

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Error().Err(err).Msg("NewWatcher failed:")
		return
	}

	defer func() {
		watcher.Close()
		log.Info().Msg("PCAP watcher is closed!")
		for i, s := range sources {
			log.Info().Int("i", i).Msg("Source is closed!")
			s.Close()

		}
	}()

	go func() {
		for {
			_, _, err := ws.ReadMessage()
			if err != nil {
				log.Info().Err(err).Msg("WebSocket read:")
				done = true
				shutdown <- true
				shutdown <- true
				return
			}
		}
	}()

	for _, pcap := range pcapFiles {
		if done {
			break
		}
		s, ok := createPcapSource(pcap.Name())
		if !ok {
			continue
		}
		sources = append(sources, s)

		assembler := createNewAsssembler(s, pcap.Name(), outputChannel, opts)
		assemblerSlice = append(assemblerSlice, assembler)

		handlePcapSource(s, pcap.Name(), assembler)
	}

	ticker := time.NewTicker(5 * time.Second)
	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if event.Op&fsnotify.Rename == fsnotify.Rename || event.Op&fsnotify.Create == fsnotify.Create {
					_, filename := filepath.Split(event.Name)
					s, ok := createPcapSource(filename)
					if ok {
						sources = append(sources, s)

						assembler := createNewAsssembler(s, filename, outputChannel, opts)
						assemblerSlice = append(assemblerSlice, assembler)

						handlePcapSource(s, filename, assembler)
					}
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Warn().Err(err).Msg("Watcher error:")
			case <-ticker.C:
				for _, assembler := range assemblerSlice {
					assembler.PeriodicClean()
				}
			case <-shutdown:
				log.Info().Msg("Shutdown recieved!")
				return
			}
		}
	}()

	err = watcher.Add(misc.GetPcapsDir())
	if err != nil {
		log.Error().Err(err).Msg("Add failed:")
		return
	}
	<-shutdown

	log.Info().Msg("WebSocket is closed!")
}

func createPcapSource(id string) (s *source.TcpPacketSource, ok bool) {
	ok = true
	if strings.HasSuffix(id, "tmp") {
		ok = false
		return
	}

	log.Debug().Str("pcap", id).Msg("Reading:")
	var err error
	s, err = source.NewTcpPacketSource(id, misc.GetPcapPath(id), "", "libpcap")
	if err != nil {
		ok = false
		log.Error().Err(err).Str("pcap", id).Msg("Failed to create packet source!")
		return
	}

	return
}

func createNewAsssembler(s *source.TcpPacketSource, id string, outputChannel chan *api.OutputChannelItem, opts *misc.Opts) *assemblers.TcpAssembler {
	return assemblers.NewTcpAssembler(
		id,
		false,
		outputChannel,
		assemblers.NewTcpStreamMap(false),
		opts,
	)
}

func handlePcapSource(s *source.TcpPacketSource, id string, assembler *assemblers.TcpAssembler) {
	packets := make(chan source.TcpPacketInfo)
	pcapPath := misc.GetPcapPath(id)
	go s.ReadPackets(packets, false, false)

	if _, ok := misc.AlivePcaps.Load(pcapPath); ok {
		go processPackets(s, assembler, packets)
	} else {
		processPackets(s, assembler, packets)
	}
}

func processPackets(s *source.TcpPacketSource, assembler *assemblers.TcpAssembler, packets chan source.TcpPacketInfo) {
	for {
		packetInfo, ok := <-packets
		if !ok {
			break
		}
		assembler.ProcessPacket(packetInfo, false)
	}

	s.Close()
}

func writeChannelToSocket(outputChannel <-chan *api.OutputChannelItem, ws *websocket.Conn, worker string, node string, query string, shutdown chan bool) {
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
		entry.Tls = misc.IsTls(entry.Stream)

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
