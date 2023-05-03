package assemblers

import (
	"sync"
	"time"

	"github.com/kubeshark/gopacket"
	"github.com/kubeshark/worker/misc"
	"github.com/kubeshark/worker/misc/wcap"
	"github.com/kubeshark/worker/pkg/api"
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
	assembler      *TcpAssembler
	isClosed       bool
	protocol       *api.Protocol
	isTargeted     bool
	client         *tcpReader
	server         *tcpReader
	counterPairs   []*api.CounterPair
	reqResMatchers []api.RequestResponseMatcher
	createdAt      time.Time
	streamsMap     api.TcpStreamMap
	tls            bool
	sync.Mutex
}

func NewTcpStream(
	pcapId string,
	assembler *TcpAssembler,
	isTargeted bool,
	streamsMap api.TcpStreamMap,
) *tcpStream {
	t := &tcpStream{
		pcapId:     pcapId,
		assembler:  assembler,
		isTargeted: isTargeted,
		streamsMap: streamsMap,
		createdAt:  time.Now(),
	}

	return t
}

func (t *tcpStream) writePacket(ci gopacket.CaptureInfo, data []byte) {
	if t.assembler.captureMode == MasterCapture {
		if err := t.assembler.GetMasterPcap().WritePacket(ci, data); err != nil {
			log.Error().Str("pcap", t.assembler.GetMasterPcap().file.Name()).Err(err).Msg("Couldn't write the packet:")
		}
	}

	t.assembler.SendSortedPacket(&wcap.SortedPacket{
		PCAP: t.pcapId,
		CI:   ci,
		Data: data,
	})
}

func (t *tcpStream) getId() int64 {
	return t.id
}

func (t *tcpStream) setId(id int64) {
	t.id = id
	if t.assembler.captureMode != ItemCapture {
		t.pcapId = misc.BuildPcapFilename(t.id)
	}
}

func (t *tcpStream) close() {
	t.Lock()
	defer t.Unlock()

	if t.isClosed {
		return
	}

	t.isClosed = true

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

func (t *tcpStream) SetProtocol(protocol *api.Protocol) {
	t.Lock()
	t.protocol = protocol

	// Clean the buffers
	t.client.msgBufferMaster = make([]api.TcpReaderDataMsg, 0)
	t.server.msgBufferMaster = make([]api.TcpReaderDataMsg, 0)
	t.Unlock()
}

func (t *tcpStream) GetPcapId() string {
	return t.pcapId
}

func (t *tcpStream) GetIndex() int64 {
	return t.itemCount
}

func (t *tcpStream) ShouldWritePackets() bool {
	return t.assembler.captureMode == MasterCapture || t.IsSortCapture()
}

func (t *tcpStream) IsSortCapture() bool {
	return t.assembler.captureMode == SortCapture
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

func (t *tcpStream) GetTls() bool {
	return t.tls
}
