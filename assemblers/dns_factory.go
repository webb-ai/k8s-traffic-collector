package assemblers

import (
	"fmt"
	"time"

	"github.com/kubeshark/gopacket"
	"github.com/kubeshark/gopacket/layers"
	"github.com/kubeshark/worker/kubernetes/resolver"
	"github.com/kubeshark/worker/misc"
	"github.com/kubeshark/worker/misc/ethernet"
	"github.com/kubeshark/worker/misc/wcap"
	"github.com/kubeshark/worker/pkg/api"
	"github.com/kubeshark/worker/pkg/extensions"
	"github.com/rs/zerolog/log"
	"k8s.io/apimachinery/pkg/watch"
)

type dnsFactory struct {
	pcapId        string
	assembler     *TcpAssembler
	outputChannel chan *api.OutputChannelItem
	streamsMap    api.TcpStreamMap
	idMap         map[uint16]int64
	opts          *misc.Opts
}

func NewDnsFactory(
	pcapId string,
	assembler *TcpAssembler,
	outputChannel chan *api.OutputChannelItem,
	streamsMap api.TcpStreamMap,
	opts *misc.Opts,
) *dnsFactory {
	return &dnsFactory{
		pcapId:        pcapId,
		assembler:     assembler,
		outputChannel: outputChannel,
		streamsMap:    streamsMap,
		idMap:         make(map[uint16]int64),
		opts:          opts,
	}
}

func (factory *dnsFactory) writePacket(ci gopacket.CaptureInfo, data []byte, pcapName string) {
	if factory.assembler.captureMode == MasterCapture {
		if err := factory.assembler.GetMasterPcap().WritePacket(ci, data); err != nil {
			log.Error().Str("pcap", factory.assembler.GetMasterPcap().file.Name()).Err(err).Msg("Couldn't write the packet:")
		}
	}

	factory.assembler.SendSortedPacket(&wcap.SortedPacket{
		PCAP: pcapName,
		CI:   ci,
		Data: data,
	})
}

func (factory *dnsFactory) handlePacket(packet gopacket.Packet, dnsID uint16) {
	var pcapName string
	if factory.assembler.captureMode != ItemCapture {
		var id int64
		var ok bool
		id, ok = factory.idMap[dnsID]
		if !ok {
			id = factory.streamsMap.NextId()
			factory.idMap[dnsID] = id
		}
		pcapName = misc.BuildUdpPcapFilename(id)
	}

	factory.writeWithEthernetLayer(packet, pcapName)
}

func (factory *dnsFactory) writeWithEthernetLayer(packet gopacket.Packet, pcapName string) {
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

	info := packet.Metadata().CaptureInfo
	info.Length = len(outgoingPacket)
	info.CaptureLength = len(outgoingPacket)
	info.Timestamp = info.Timestamp.UTC()

	factory.writePacket(info, outgoingPacket, pcapName)
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

	pcapId := factory.pcapId
	if pcapId == "" {
		id, ok := factory.idMap[dns.ID]
		if ok {
			pcapId = misc.BuildUdpPcapFilename(id)
		}
	}

	item := api.OutputChannelItem{
		Index:          0,
		Stream:         pcapId,
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

	delete(factory.idMap, dns.ID)
}
