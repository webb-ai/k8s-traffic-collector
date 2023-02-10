package vm

import (
	"errors"
	"time"

	"github.com/kubeshark/gopacket"
)

type CustomPacketInfo struct {
	Timestamp     time.Time `json:"timestamp"`
	CaptureLength int       `json:"captureLength"`
	Length        int       `json:"length"`
	Truncated     bool      `json:"truncated"`
}

func BuildCustomPacketInfo(packet gopacket.Packet) (*CustomPacketInfo, error) {
	if packet == nil {
		return nil, errors.New("Packet is nil")
	}
	metadata := packet.Metadata()
	if metadata == nil {
		return nil, errors.New("Metadata is nil")
	}
	return &CustomPacketInfo{
		Timestamp:     packet.Metadata().Timestamp,
		CaptureLength: packet.Metadata().CaptureLength,
		Length:        packet.Metadata().Length,
		Truncated:     packet.Metadata().Truncated,
	}, nil
}
