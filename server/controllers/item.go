package controllers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/kubeshark/worker/assemblers"
	"github.com/kubeshark/worker/misc"
	"github.com/kubeshark/worker/pkg/api"
	"github.com/kubeshark/worker/pkg/extensions"
	"github.com/kubeshark/worker/pkg/languages/kfl"
	"github.com/kubeshark/worker/source"
	"github.com/kubeshark/worker/utils"
	"github.com/kubeshark/worker/vm"
	"github.com/rs/zerolog/log"
)

func GetItem(c *gin.Context, opts *misc.Opts) {
	_id := c.Param("id")
	idIndex := strings.Split(_id, "-")
	if len(idIndex) < 2 {
		msg := "Malformed ID!"
		log.Error().Str("id", _id).Msg(msg)
		misc.HandleError(c, fmt.Errorf(msg))
		return
	}
	id := idIndex[0]
	index, err := strconv.ParseInt(idIndex[1], 0, 64)
	if err != nil {
		log.Error().Err(err).Str("pcap", id).Str("index", idIndex[1]).Msg("Failed parsing index!")
		misc.HandleError(c, err)
		return
	}

	query := c.Query("q")
	context := c.Query("c")
	worker := c.Query("worker")
	node := c.Query("node")

	outputChannel := make(chan *api.OutputChannelItem)

	streamsMap := assemblers.NewTcpStreamMap()
	packets := make(chan source.TcpPacketInfo)
	s, err := source.NewTcpPacketSource(id, misc.GetPcapPath(id, context), "", "libpcap")
	if err != nil {
		log.Error().Err(err).Str("pcap", id).Msg("Failed to create packet source!")
		c.String(http.StatusNotFound, fmt.Sprintf("The TCP/UDP stream %s was removed from the node: %s/%s", id, node, context))
		return
	}
	go s.ReadPackets(packets, false, false, nil)

	assembler := assemblers.NewTcpAssembler(id, assemblers.ItemCapture, nil, outputChannel, streamsMap, opts)
	go func() {
		for {
			packetInfo, ok := <-packets
			if !ok {
				break
			}
			assembler.ProcessPacket(packetInfo, false)
		}
	}()

	defer s.Close()

	var i int64 = -1
	for item := range outputChannel {
		i++
		if i < index {
			continue
		}

		// TODO: The previously bad design forces us to Marshal and Unmarshal
		var data []byte
		data, err = json.Marshal(item)
		if err != nil {
			log.Error().Err(err).Msg("Failed marshalling item:")
			break
		}
		var finalItem *api.OutputChannelItem
		err = json.Unmarshal(data, &finalItem)
		if err != nil {
			log.Error().Err(err).Msg("Failed unmarshalling item:")
			misc.HandleError(c, err)
			break
		}

		entry := utils.ItemToEntry(finalItem)
		entry.Worker = worker
		entry.Node.IP = misc.RemovePortFromWorkerHost(worker)
		entry.Node.Name = node
		entry.BuildId()

		extension := extensions.ExtensionsMap[entry.Protocol.Name]

		var entryMarshaled []byte
		entryMarshaled, err = json.Marshal(entry)
		if err != nil {
			log.Error().Err(err).Msg("Failed marshalling entry:")
			break
		}

		var record string
		_, record, err = kfl.Apply(entryMarshaled, query)
		if err != nil {
			log.Error().Err(err).Msg("Failed applying query:")
			break
		}

		var alteredEntry *api.Entry
		err = json.Unmarshal([]byte(record), &alteredEntry)
		if err != nil {
			log.Error().Err(err).Msg("Failed unmarshalling altered entry:")
			break
		}

		alteredEntry = vm.ItemQueriedHook(alteredEntry)

		base := extension.Dissector.Summarize(alteredEntry)
		var representation []byte
		representation, err = extension.Dissector.Represent(alteredEntry.Request, alteredEntry.Response)
		if err != nil {
			log.Error().Err(err).Msg("Failed representing altered entry:")
			break
		}

		entryWrapped := &api.EntryWrapper{
			Protocol:       entry.Protocol,
			Representation: string(representation),
			Data:           entry,
			Base:           base,
		}

		c.JSON(http.StatusOK, entryWrapped)
		return
	}

	misc.HandleError(c, err)
}
