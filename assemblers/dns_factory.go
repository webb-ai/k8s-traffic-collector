package assemblers

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/kubeshark/gopacket"
	"github.com/kubeshark/gopacket/layers"
	"github.com/kubeshark/gopacket/pcapgo"
	"github.com/kubeshark/worker/kubernetes/resolver"
	"github.com/kubeshark/worker/misc"
	"github.com/kubeshark/worker/misc/ethernet"
	"github.com/kubeshark/worker/pkg/api"
	"github.com/kubeshark/worker/pkg/extensions"
	"github.com/rs/zerolog/log"
	"k8s.io/apimachinery/pkg/watch"
)

type dnsFactory struct {
	pcapId        string
	identifyMode  bool
	outputChannel chan *api.OutputChannelItem
	streamsMap    api.TcpStreamMap
	idMap         map[uint16]int64
	pcapMap       map[uint16]*os.File
	pcapWriterMap map[uint16]*pcapgo.Writer
	opts          *misc.Opts
}

func NewDnsFactory(pcapId string, identifyMode bool, outputChannel chan *api.OutputChannelItem, streamsMap api.TcpStreamMap, opts *misc.Opts) *dnsFactory {
	return &dnsFactory{
		pcapId:        pcapId,
		identifyMode:  identifyMode,
		outputChannel: outputChannel,
		streamsMap:    streamsMap,
		idMap:         make(map[uint16]int64),
		pcapMap:       make(map[uint16]*os.File),
		pcapWriterMap: make(map[uint16]*pcapgo.Writer),
		opts:          opts,
	}
}

func (factory *dnsFactory) writePacket(packet gopacket.Packet, dnsID uint16) {
	if factory.identifyMode {
		var pcap *os.File
		var pcapWriter *pcapgo.Writer
		var err error

		_, ok := factory.idMap[dnsID]
		if !ok {
			id := factory.streamsMap.NextId()

			pcapPath := misc.BuildUdpPcapPath(id)
			log.Debug().Str("file", pcapPath).Msg("Dumping DNS stream:")

			pcap, err = os.OpenFile(pcapPath, os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				log.Error().Int("dns-id", int(dnsID)).Err(err).Msg("Couldn't create PCAP:")
				return
			} else {
				pcapWriter = pcapgo.NewWriter(pcap)
				err = pcapWriter.WriteFileHeader(uint32(misc.Snaplen), layers.LinkTypeEthernet)
				if err != nil {
					log.Error().Err(err).Msg("While writing the PCAP header:")
				} else {
					log.Debug().Str("file", pcapPath).Msg("WROTE HEADER:")
				}
			}

			factory.pcapId = filepath.Base(pcapPath)

			factory.idMap[dnsID] = id
			factory.pcapMap[dnsID] = pcap
			factory.pcapWriterMap[dnsID] = pcapWriter
		} else {
			pcap = factory.pcapMap[dnsID]
			pcapWriter = factory.pcapWriterMap[dnsID]
		}

		if pcapWriter != nil {
			factory.writeWithEthernetLayer(packet, pcap, pcapWriter)
		}
	}
}

func (factory *dnsFactory) writeWithEthernetLayer(packet gopacket.Packet, pcap *os.File, pcapWriter *pcapgo.Writer) {
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

	// UDP layer
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return
	}
	serializableLayers = append(serializableLayers, udpLayer.(*layers.UDP))

	// DNS layer
	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		return
	}
	serializableLayers = append(serializableLayers, dnsLayer.(*layers.DNS))

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: false}
	err := gopacket.SerializeLayers(buf, opts, serializableLayers...)
	if err != nil {
		log.Error().Err(err).Msg("Error serializing packet:")
		return
	}

	newPacket := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Lazy)

	outgoingPacket := newPacket.Data()

	info := newPacket.Metadata().CaptureInfo
	info.Length = len(outgoingPacket)
	info.CaptureLength = len(outgoingPacket)
	info.Timestamp = info.Timestamp.UTC()

	if err := pcapWriter.WritePacket(info, outgoingPacket); err != nil {
		log.Debug().Str("pcap", pcap.Name()).Err(err).Msg("Couldn't write the packet:")
	}
}

func (factory *dnsFactory) emitItem(packet gopacket.Packet, dns *layers.DNS) {
	connetionInfo := &api.ConnectionInfo{}

	// IPv4 layer
	ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
	if ipv4Layer != nil {
		_ipv4Layer := ipv4Layer.(*layers.IPv4)
		connetionInfo.ClientIP = _ipv4Layer.DstIP.String()
		connetionInfo.ServerIP = _ipv4Layer.SrcIP.String()
	}

	// IPv6 layer
	ipv6Layer := packet.Layer(layers.LayerTypeIPv6)
	if ipv4Layer == nil && ipv6Layer != nil {
		_ipv6Layer := ipv6Layer.(*layers.IPv6)
		connetionInfo.ClientIP = _ipv6Layer.DstIP.String()
		connetionInfo.ServerIP = _ipv6Layer.SrcIP.String()
	}

	if ipv4Layer == nil && ipv6Layer == nil {
		return
	}

	// UDP layer
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return
	}

	_udpLayer := udpLayer.(*layers.UDP)
	if _udpLayer.SrcPort != 53 {
		return
	}

	connetionInfo.ClientPort = fmt.Sprintf("%d", _udpLayer.DstPort)
	connetionInfo.ServerPort = fmt.Sprintf("%d", _udpLayer.SrcPort)

	dnsExtension := extensions.ExtensionsMap["dns"]

	req := api.GenericMessage{
		IsRequest:   true,
		CaptureTime: packet.Metadata().Timestamp,
		CaptureSize: packet.Metadata().CaptureLength,
		Payload:     mapDNSLayerToRequest(dns),
	}

	res := api.GenericMessage{
		IsRequest:   false,
		CaptureTime: packet.Metadata().Timestamp,
		CaptureSize: packet.Metadata().CaptureLength,
		Payload:     mapDNSLayerToResponse(dns),
	}

	item := api.OutputChannelItem{
		Index:          0,
		Stream:         factory.pcapId,
		Protocol:       *dnsExtension.Protocol,
		Timestamp:      req.CaptureTime.UnixNano() / int64(time.Millisecond),
		ConnectionInfo: connetionInfo,
		Pair: &api.RequestResponsePair{
			Request:  req,
			Response: res,
		},
	}

	isTargeted := !factory.opts.ClusterMode
	if factory.opts.ClusterMode {
		if inArrayPod(misc.TargetedPods, fmt.Sprintf("%s:%s", connetionInfo.ServerIP, connetionInfo.ServerPort)) {
			isTargeted = true
		} else if inArrayPod(misc.TargetedPods, connetionInfo.ServerIP) {
			isTargeted = true
		} else if inArrayPod(misc.TargetedPods, fmt.Sprintf("%s:%s", connetionInfo.ClientIP, connetionInfo.ClientPort)) {
			isTargeted = true
		} else if inArrayPod(misc.TargetedPods, connetionInfo.ClientIP) {
			isTargeted = true
		}
	}

	if !isTargeted {
		return
	}

	factory.outputChannel <- &item

	if len(dns.Answers) > 0 && len(dns.Questions) > 0 {
		resolver.K8sResolver.SaveResolution(dns.Answers[0].IP.String(), &api.Resolution{
			Name: string(dns.Questions[0].Name),
		}, watch.Added)
	}

	pcap := factory.pcapMap[dns.ID]
	pcap.Close()

	delete(factory.idMap, dns.ID)
	delete(factory.pcapMap, dns.ID)
	delete(factory.pcapWriterMap, dns.ID)

	if !isTargeted {
		os.Remove(misc.GetPcapPath(pcap.Name()))
	}

}
