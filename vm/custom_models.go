package vm

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/kubeshark/gopacket"
)

type CustomPacketInfo struct {
	Timestamp     time.Time `json:"timestamp"`
	CaptureLength int       `json:"captureLength"`
	Length        int       `json:"length"`
	Truncated     bool      `json:"truncated"`
	Fragmented    bool      `json:"fragmented"`
}

func BuildCustomPacketInfo(packet gopacket.Packet, fragmented bool) (info map[string]interface{}, err error) {
	if packet == nil {
		err = errors.New("Packet is nil")
		return
	}
	metadata := packet.Metadata()
	if metadata == nil {
		err = errors.New("Metadata is nil")
		return
	}

	cpi := &CustomPacketInfo{
		Timestamp:     packet.Metadata().Timestamp,
		CaptureLength: packet.Metadata().CaptureLength,
		Length:        packet.Metadata().Length,
		Truncated:     packet.Metadata().Truncated,
		Fragmented:    fragmented,
	}

	var data []byte
	data, err = json.Marshal(cpi)
	if err != nil {
		return
	}

	err = json.Unmarshal(data, &info)
	if err != nil {
		return
	}

	return
}
