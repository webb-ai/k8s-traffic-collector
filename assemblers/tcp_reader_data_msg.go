package assemblers

import (
	"time"

	"github.com/kubeshark/gopacket"
	"github.com/kubeshark/worker/api"
)

type tcpReaderDataMsg struct {
	bytes []byte
	ci    gopacket.CaptureInfo
}

func NewTcpReaderDataMsg(data []byte, ci gopacket.CaptureInfo) api.TcpReaderDataMsg {
	return &tcpReaderDataMsg{data, ci}
}

func (dataMsg *tcpReaderDataMsg) GetBytes() []byte {
	return dataMsg.bytes
}

func (dataMsg *tcpReaderDataMsg) GetTimestamp() time.Time {
	return dataMsg.ci.Timestamp.UTC()
}

func (dataMsg *tcpReaderDataMsg) GetCaptureInfo() gopacket.CaptureInfo {
	return dataMsg.ci
}
