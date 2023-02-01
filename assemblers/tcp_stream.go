package assemblers

import (
	"os"
	"sync"
	"time"

	"github.com/kubeshark/base/pkg/api"
	"github.com/kubeshark/gopacket/layers"
	"github.com/kubeshark/gopacket/pcapgo"
	"github.com/kubeshark/worker/misc"
	"github.com/rs/zerolog/log"
)

/* It's a connection (bidirectional)
 * Implements gopacket.reassembly.Stream interface (Accept, ReassembledSG, ReassemblyComplete)
 * ReassembledSG gets called when new reassembled data is ready (i.e. bytes in order, no duplicates, complete)
 * In our implementation, we pass information from ReassembledSG to the TcpReader through a shared channel.
 */
type tcpStream struct {
	id             int64
	pcapId         string
	itemCount      int64
	identifyMode   bool
	emittable      bool
	isClosed       bool
	protocol       *api.Protocol
	isTargeted     bool
	client         *tcpReader
	server         *tcpReader
	counterPairs   []*api.CounterPair
	reqResMatchers []api.RequestResponseMatcher
	createdAt      time.Time
	streamsMap     api.TcpStreamMap
	pcap           *os.File
	pcapWriter     *pcapgo.Writer
	sync.Mutex
}

func NewTcpStream(pcapId string, identifyMode bool, isTargeted bool, streamsMap api.TcpStreamMap) *tcpStream {
	t := &tcpStream{
		pcapId:       pcapId,
		identifyMode: identifyMode,
		isTargeted:   isTargeted,
		streamsMap:   streamsMap,
		createdAt:    time.Now(),
	}

	return t
}

func (t *tcpStream) createPcapWriter() {
	if t.GetIsIdentifyMode() {
		tmpPcapPath := misc.BuildTmpPcapPath(t.id)
		log.Debug().Str("file", tmpPcapPath).Msg("Dumping TCP stream:")

		var err error
		t.pcap, err = os.OpenFile(tmpPcapPath, os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Error().Err(err).Msg("Couldn't create PCAP:")
		} else {
			t.pcapWriter = pcapgo.NewWriter(t.pcap)
			err = t.pcapWriter.WriteFileHeader(uint32(misc.Snaplen), layers.LinkTypeEthernet)
			if err != nil {
				log.Error().Err(err).Msg("While writing the PCAP header:")
			}
		}
	}
}

func (t *tcpStream) handlePcapDissectionResult() {
	if t.GetIsIdentifyMode() && !t.isEmittable() {
		tmpPcapPath := misc.BuildTmpPcapPath(t.id)
		log.Debug().Str("file", tmpPcapPath).Int("id", int(t.id)).Msg("Removing PCAP:")
		os.Remove(tmpPcapPath)
	}
}

func (t *tcpStream) getId() int64 {
	return t.id
}

func (t *tcpStream) setId(id int64) {
	t.id = id
	t.createPcapWriter()
}

func (t *tcpStream) close() {
	t.Lock()
	defer t.Unlock()

	if t.isClosed {
		return
	}

	t.isClosed = true

	if t.pcap != nil && t.GetIsIdentifyMode() {
		log.Debug().Str("pcap", t.pcap.Name()).Msg("Closing:")
		t.pcap.Close()
		pcapPath := misc.BuildPcapPath(t.id)
		misc.AlivePcaps.Delete(pcapPath)
	}

	t.streamsMap.Delete(t.id)
	t.client.close()
	t.server.close()
}

func (t *tcpStream) addCounterPair(counterPair *api.CounterPair) {
	t.counterPairs = append(t.counterPairs, counterPair)
}

func (t *tcpStream) addReqResMatcher(reqResMatcher api.RequestResponseMatcher) {
	t.reqResMatchers = append(t.reqResMatchers, reqResMatcher)
}

func (t *tcpStream) isEmittable() bool {
	return t.emittable
}

func (t *tcpStream) SetProtocol(protocol *api.Protocol) {
	t.protocol = protocol

	// Clean the buffers
	t.Lock()
	t.client.msgBufferMaster = make([]api.TcpReaderDataMsg, 0)
	t.server.msgBufferMaster = make([]api.TcpReaderDataMsg, 0)
	t.Unlock()
}

func (t *tcpStream) SetAsEmittable() {
	if t.GetIsIdentifyMode() && !t.isEmittable() {
		tmpPcapPath := misc.BuildTmpPcapPath(t.id)
		pcapPath := misc.BuildPcapPath(t.id)
		misc.AlivePcaps.Store(pcapPath, true)
		log.Debug().Str("old", tmpPcapPath).Str("new", pcapPath).Msg("Renaming PCAP:")
		err := os.Rename(tmpPcapPath, pcapPath)
		if err != nil {
			log.Error().Err(err).Str("pcap", tmpPcapPath).Msg("Couldn't rename the PCAP file:")
		}
	}
	t.emittable = true
}

func (t *tcpStream) GetPcapId() string {
	return t.pcapId
}

func (t *tcpStream) GetIndex() int64 {
	return t.itemCount
}

func (t *tcpStream) GetIsIdentifyMode() bool {
	return t.identifyMode
}

func (t *tcpStream) GetReqResMatchers() []api.RequestResponseMatcher {
	return t.reqResMatchers
}

func (t *tcpStream) GetIsTargeted() bool {
	return t.isTargeted
}

func (t *tcpStream) GetIsClosed() bool {
	return t.isClosed
}

func (t *tcpStream) IncrementItemCount() {
	t.itemCount++
}
