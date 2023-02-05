package assemblers

import (
	"encoding/binary"
	"sync/atomic"

	"github.com/kubeshark/gopacket"
	"github.com/kubeshark/gopacket/layers" // pulls in all layers decoders
	"github.com/kubeshark/gopacket/reassembly"
	"github.com/kubeshark/worker/diagnose"
	"github.com/kubeshark/worker/misc/ethernet"
	"github.com/rs/zerolog/log"
)

type tcpReassemblyStream struct {
	ident           string
	tcpState        *reassembly.TCPSimpleFSM
	fsmerr          bool
	optchecker      reassembly.TCPOptionCheck
	isDNS           bool
	tcpStream       *tcpStream
	notignorefsmerr bool
	optcheck        bool
	checksum        bool
}

func NewTcpReassemblyStream(ident string, tcp *layers.TCP, fsmOptions reassembly.TCPSimpleFSMOptions, stream *tcpStream) reassembly.Stream {
	return &tcpReassemblyStream{
		ident:      ident,
		tcpState:   reassembly.NewTCPSimpleFSM(fsmOptions),
		optchecker: reassembly.NewTCPOptionCheck(),
		isDNS:      tcp.SrcPort == 53 || tcp.DstPort == 53,
		tcpStream:  stream,
	}
}

func (t *tcpReassemblyStream) Accept(tcp *layers.TCP, ci gopacket.CaptureInfo, dir reassembly.TCPFlowDirection, nextSeq reassembly.Sequence, start *bool, ac reassembly.AssemblerContext) bool {
	// FSM
	if !t.tcpState.CheckState(tcp, dir) {
		diagnose.ErrorsMap.SilentError("FSM-rejection", "%s: Packet rejected by FSM (state:%s)", t.ident, t.tcpState.String())
		diagnose.InternalStats.RejectFsm++
		if !t.fsmerr {
			t.fsmerr = true
			diagnose.InternalStats.RejectConnFsm++
		}
		if t.notignorefsmerr {
			return false
		}
	}
	// Options
	err := t.optchecker.Accept(tcp, ci, dir, nextSeq, start)
	if err != nil {
		diagnose.ErrorsMap.SilentError("OptionChecker-rejection", "%s: Packet rejected by OptionChecker: %s", t.ident, err)
		diagnose.InternalStats.RejectOpt++
		if t.optcheck {
			return false
		}
	}
	// Checksum
	accept := true
	if t.checksum {
		c, err := tcp.ComputeChecksum()
		if err != nil {
			diagnose.ErrorsMap.SilentError("ChecksumCompute", "%s: Got error computing checksum: %s", t.ident, err)
			accept = false
		} else if c != 0x0 {
			diagnose.ErrorsMap.SilentError("Checksum", "%s: Invalid checksum: 0x%x", t.ident, c)
			accept = false
		}
	}
	if !accept {
		diagnose.InternalStats.RejectOpt++
	}

	*start = true

	return accept
}

func (t *tcpReassemblyStream) ReassembledSG(sg reassembly.ScatterGather, ac reassembly.AssemblerContext) {
	dir, _, _, skip := sg.Info()
	length, saved := sg.Lengths()
	// update stats
	sgStats := sg.Stats()
	if skip > 0 {
		atomic.AddInt64(&diagnose.InternalStats.MissedBytes, int64(skip))
	}
	atomic.AddInt64(&diagnose.InternalStats.Sz, int64(length-saved))
	atomic.AddInt64(&diagnose.InternalStats.Pkt, int64(sgStats.Packets))
	if sgStats.Chunks > 1 {
		diagnose.InternalStats.Reassembled++
	}
	atomic.AddInt64(&diagnose.InternalStats.OutOfOrderPackets, int64(sgStats.QueuedPackets))
	atomic.AddInt64(&diagnose.InternalStats.OutOfOrderBytes, int64(sgStats.QueuedBytes))
	if int64(length) > diagnose.InternalStats.BiggestChunkBytes {
		atomic.StoreInt64(&diagnose.InternalStats.BiggestChunkBytes, int64(length))
	}
	if int64(sgStats.Packets) > diagnose.InternalStats.BiggestChunkPackets {
		atomic.StoreInt64(&diagnose.InternalStats.BiggestChunkPackets, int64(sgStats.Packets))
	}
	if sgStats.OverlapBytes != 0 && sgStats.OverlapPackets == 0 {
		// In the original example this was handled with panic().
		// I don't know what this error means or how to handle it properly.
		diagnose.ErrorsMap.SilentError("Invalid-Overlap", "bytes:%d, pkts:%d", sgStats.OverlapBytes, sgStats.OverlapPackets)
	}
	atomic.AddInt64(&diagnose.InternalStats.OverlapBytes, int64(sgStats.OverlapBytes))
	atomic.AddInt64(&diagnose.InternalStats.OverlapPackets, int64(sgStats.OverlapPackets))

	if skip != -1 && skip != 0 {
		// Missing bytes in stream: do not even try to parse it
		return
	}
	data := sg.Fetch(length)
	if t.isDNS {
		dns := &layers.DNS{}
		var decoded []gopacket.LayerType
		if len(data) < 2 {
			if len(data) > 0 {
				sg.KeepFrom(0)
			}
			return
		}
		dnsSize := binary.BigEndian.Uint16(data[:2])
		missing := int(dnsSize) - len(data[2:])
		diagnose.ErrorsMap.Debug("dnsSize: %d, missing: %d", dnsSize, missing)
		if missing > 0 {
			diagnose.ErrorsMap.Debug("Missing some bytes: %d", missing)
			sg.KeepFrom(0)
			return
		}
		p := gopacket.NewDecodingLayerParser(layers.LayerTypeDNS, dns)
		err := p.DecodeLayers(data[2:], &decoded)
		if err != nil {
			diagnose.ErrorsMap.SilentError("DNS-parser", "Failed to decode DNS: %v", err)
		} else {
			diagnose.ErrorsMap.Debug("DNS: %s", gopacket.LayerDump(dns))
		}
		if len(data) > 2+int(dnsSize) {
			sg.KeepFrom(2 + int(dnsSize))
		}
	} else if t.tcpStream.GetIsTargeted() {
		if length > 0 {
			// This is where we pass the reassembled information onwards
			// This channel is read by an tcpReader object
			diagnose.AppStats.IncReassembledTcpPayloadsCount()
			ci := ac.GetCaptureInfo()
			if dir == reassembly.TCPDirClientToServer {
				t.tcpStream.client.sendMsgIfNotClosed(NewTcpReaderDataMsg(data, ci))
			} else {
				t.tcpStream.server.sendMsgIfNotClosed(NewTcpReaderDataMsg(data, ci))
			}
		}
	}
}

func (t *tcpReassemblyStream) ReassemblyComplete(ac reassembly.AssemblerContext) bool {
	if t.tcpStream.GetIsTargeted() && !t.tcpStream.GetIsClosed() {
		t.tcpStream.close()
	}

	return true
}

func (t *tcpReassemblyStream) ReceivePacket(packet gopacket.Packet) {
	if t.tcpStream.GetIsTargeted() && t.tcpStream.GetIsIdentifyMode() {
		t.writeWithEthernetLayer(packet)
	}
}

func (t *tcpReassemblyStream) writeWithEthernetLayer(packet gopacket.Packet) {
	var serializableLayers []gopacket.SerializableLayer

	// Get Linux SLL layer
	linuxSLLLayer := packet.Layer(layers.LayerTypeLinuxSLL)
	if linuxSLLLayer == nil {
		// If Linux SLL layer is not present then it means we're reading a PCAP file
		ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
		if ethernetLayer == nil {
			// Ignore the packets that neither Linux SLL nor Ethernet layer
			return
		}

		// Ethernet layer
		serializableLayers = []gopacket.SerializableLayer{ethernetLayer.(*layers.Ethernet)}
	} else {
		linuxSLL := linuxSLLLayer.(*layers.LinuxSLL)
		// Ethernet layer
		serializableLayers = []gopacket.SerializableLayer{ethernet.NewEthernetLayer(linuxSLL.EthernetType)}
	}

	// IPv4 layer
	ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
	if ipv4Layer != nil {
		serializableLayers = append(serializableLayers, ipv4Layer.(*layers.IPv4))
	}

	// IPv6 layer
	ipv6Layer := packet.Layer(layers.LayerTypeIPv6)
	if ipv4Layer == nil && ipv6Layer != nil {
		serializableLayers = append(serializableLayers, ipv6Layer.(*layers.IPv6))
	}

	if ipv4Layer == nil && ipv6Layer == nil {
		return
	}

	// TCP layer
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return
	}
	serializableLayers = append(serializableLayers, tcpLayer.(*layers.TCP))

	// Payload
	applicationLayer := packet.ApplicationLayer()
	if applicationLayer != nil {
		serializableLayers = append(serializableLayers, gopacket.Payload(applicationLayer.Payload()))
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: false}
	err := gopacket.SerializeLayers(buf, opts, serializableLayers...)
	if err != nil {
		log.Error().Err(err).Msg("Error serializing packet:")
		return
	}

	newPacket := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Lazy)

	t.writePacket(newPacket)
}

func (t *tcpReassemblyStream) writePacket(packet gopacket.Packet) {
	outgoingPacket := packet.Data()

	info := packet.Metadata().CaptureInfo
	info.Length = len(outgoingPacket)
	info.CaptureLength = len(outgoingPacket)
	info.Timestamp = info.Timestamp.UTC()

	if t.tcpStream.pcapWriter == nil {
		log.Debug().Msg("PCAP writer for this TCP stream does not exist (too many open files)!")
		return
	}

	if err := t.tcpStream.pcapWriter.WritePacket(info, outgoingPacket); err != nil {
		log.Debug().Str("pcap", t.tcpStream.pcap.Name()).Err(err).Msg("Couldn't write the packet:")
	}
}
