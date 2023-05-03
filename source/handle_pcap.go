package source

import (
	"fmt"
	"os"
	"time"

	"github.com/kubeshark/gopacket"
	"github.com/kubeshark/gopacket/layers"
	"github.com/kubeshark/gopacket/pcap"
	"github.com/kubeshark/gopacket/pcapgo"
)

type pcapHandle struct {
	source  *gopacket.PacketSource
	capture *pcap.Handle
	file    *os.File
}

func (h *pcapHandle) NextPacket() (packet gopacket.Packet, err error) {
	return h.source.NextPacket()
}
func (h *pcapHandle) SetDecoder(decoder gopacket.Decoder, lazy bool, noCopy bool) {
	h.source = gopacket.NewPacketSource(h.capture, decoder)
	h.source.Lazy = lazy
	h.source.NoCopy = noCopy
}

func (h *pcapHandle) SetBPF(expr string) (err error) {
	return h.capture.SetBPFFilter(expr)
}

func (h *pcapHandle) LinkType() layers.LinkType {
	return h.capture.LinkType()
}

func (h *pcapHandle) Stats() (packetsReceived uint, packetsDropped uint, err error) {
	var stats *pcap.Stats
	stats, err = h.capture.Stats()
	if err != nil {
		return
	}
	packetsReceived = uint(stats.PacketsReceived)
	packetsDropped = uint(stats.PacketsDropped)
	return
}

func (h *pcapHandle) Close() (err error) {
	if h.capture == nil {
		h.file.Close()
	} else {
		h.capture.Close()
	}
	return
}

func (h *pcapHandle) FileSize() (size int64, err error) {
	var fileInfo os.FileInfo
	fileInfo, err = h.file.Stat()
	if err != nil {
		return
	}
	size = fileInfo.Size()
	return
}

func newPcapHandle(filename string, device string, snaplen int, promisc bool, tstype string) (handle Handle, err error) {
	if filename != "" {
		// Capture from PCAP file
		var file *os.File
		file, err = os.OpenFile(filename, os.O_RDONLY, 0644)
		if err != nil {
			return
		}

		var pcapReader *pcapgo.Reader
		pcapReader, err = pcapgo.NewReader(file)
		if err != nil {
			return
		}
		return &pcapHandle{
			source: gopacket.NewPacketSource(pcapReader, layers.LinkTypeEthernet),
			file:   file,
		}, nil
	}

	// Capture from a network interface
	var inactive *pcap.InactiveHandle
	inactive, err = pcap.NewInactiveHandle(device)
	if err != nil {
		err = fmt.Errorf("could not create: %v", err)
		return
	}
	defer inactive.CleanUp()
	if err = inactive.SetSnapLen(snaplen); err != nil {
		err = fmt.Errorf("could not set snap length: %v", err)
		return
	} else if err = inactive.SetPromisc(promisc); err != nil {
		err = fmt.Errorf("could not set promisc mode: %v", err)
		return
	} else if err = inactive.SetTimeout(time.Second); err != nil {
		err = fmt.Errorf("could not set timeout: %v", err)
		return
	}
	if tstype != "" {
		var t pcap.TimestampSource
		if t, err = pcap.TimestampSourceFromString(tstype); err != nil {
			err = fmt.Errorf("supported timestamp types: %v", inactive.SupportedTimestamps())
			return
		} else if err = inactive.SetTimestampSource(t); err != nil {
			err = fmt.Errorf("supported timestamp types: %v", inactive.SupportedTimestamps())
			return
		}
	}
	var capture *pcap.Handle
	if capture, err = inactive.Activate(); err != nil {
		err = fmt.Errorf("PCAP Activate error: %v", err)
		return
	}

	handle = &pcapHandle{
		capture: capture,
	}

	return
}
