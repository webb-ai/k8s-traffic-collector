package redis

import (
	"sync"

	"github.com/kubeshark/worker/pkg/api"
)

type tcpStream struct {
	pcapId         string
	itemCount      int64
	isClosed       bool
	isTargeted     bool
	reqResMatchers []api.RequestResponseMatcher
	sync.Mutex
}

func NewTcpStream() api.TcpStream {
	return &tcpStream{}
}

func (t *tcpStream) SetProtocol(protocol *api.Protocol) {}

func (t *tcpStream) GetPcapId() string {
	return t.pcapId
}

func (t *tcpStream) GetIndex() int64 {
	return t.itemCount
}

func (t *tcpStream) ShouldWritePackets() bool {
	return true
}

func (t *tcpStream) IsSortCapture() bool {
	return true
}

func (t *tcpStream) IncrementItemCount() {
	t.itemCount++
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

func (t *tcpStream) GetTls() bool {
	return false
}
