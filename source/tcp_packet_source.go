package source

import (
	"fmt"
	"io"

	"github.com/kubeshark/gopacket"
	"github.com/kubeshark/gopacket/ip4defrag"
	"github.com/kubeshark/gopacket/layers"
	"github.com/kubeshark/worker/diagnose"
	"github.com/kubeshark/worker/misc"
	"github.com/rs/zerolog/log"
)

type Handle interface {
	NextPacket() (packet gopacket.Packet, err error)
	SetDecoder(decoder gopacket.Decoder, lazy bool, noCopy bool)
	SetBPF(expr string) (err error)
	LinkType() layers.LinkType
	Stats() (packetsReceived uint, packetsDropped uint, err error)
	Close() (err error)
}

type TcpPacketSource struct {
	Handle    Handle
	defragger *ip4defrag.IPv4Defragmenter
	name      string
}

type TcpPacketInfo struct {
	Packet gopacket.Packet
	Source *TcpPacketSource
}

func NewTcpPacketSource(name, filename string, interfaceName string, packetCapture string) (*TcpPacketSource, error) {
	var err error

	result := &TcpPacketSource{
		name:      name,
		defragger: ip4defrag.NewIPv4Defragmenter(),
	}

	targetSizeMb := 8
	promisc := true
	tstype := ""
	lazy := false

	switch packetCapture {
	case "af_packet":
		result.Handle, err = newAfpacketHandle(
			interfaceName,
			targetSizeMb,
			misc.Snaplen,
		)
		if err != nil {
			return nil, err
		}
		log.Debug().Msg("Using AF_PACKET socket as the capture source")
	default:
		result.Handle, err = newPcapHandle(
			filename,
			interfaceName,
			misc.Snaplen,
			promisc,
			tstype,
		)
		if err != nil {
			return nil, err
		}
		log.Debug().Msg("Using libpcap as the capture source")
	}

	var decoder gopacket.Decoder
	var ok bool
	decoderName := result.Handle.LinkType().String()
	if decoder, ok = gopacket.DecodersByLayerName[decoderName]; !ok {
		result.Handle.Close()
		return nil, fmt.Errorf("no decoder named %v", decoderName)
	}

	result.Handle.SetDecoder(decoder, lazy, true)

	return result, nil
}

func (source *TcpPacketSource) String() string {
	return source.name
}

func (source *TcpPacketSource) setBPFFilter(expr string) (err error) {
	return source.Handle.SetBPF(expr)
}

func (source *TcpPacketSource) Close() {
	if source.Handle != nil {
		source.Handle.Close()
	}
}

func (source *TcpPacketSource) Stats() (packetsReceived uint, packetsDropped uint, err error) {
	return source.Handle.Stats()
}

func (source *TcpPacketSource) ReadPackets(packets chan<- TcpPacketInfo, dontClose bool) {
	log.Debug().Str("source", source.name).Msg("Start reading packets from:")

	for {
		packet, err := source.Handle.NextPacket()

		if err == io.EOF {
			log.Debug().Str("source", source.name).Msg("Got EOF while reading packets from:")
			if !dontClose {
				close(packets)
				log.Debug().Str("source", source.name).Msg("Closed packet channel because of EOF.")
			}
			return
		} else if err != nil {
			if err.Error() != "Timeout Expired" {
				log.Debug().Err(err).Str("source", source.name).Msg("While reading from:")
			}
			continue
		}

		// defrag the IPv4 packet if required
		if ipv4layer := packet.Layer(layers.LayerTypeIPv4); ipv4layer != nil {
			ipv4 := ipv4layer.(*layers.IPv4)
			l := ipv4.Length
			newipv4, err := source.defragger.DefragIPv4(ipv4)
			if err != nil {
				log.Debug().Err(err).Msg("While de-fragmenting!")
				continue
			} else if newipv4 == nil {
				log.Debug().Msg("Fragment...")
				continue // packet fragment, we don't have whole packet yet.
			}
			if newipv4.Length != l {
				diagnose.InternalStats.Ipdefrag++
				log.Debug().Int("layer-type", int(newipv4.NextLayerType())).Msg("Decoding re-assembled packet:")
				pb, ok := packet.(gopacket.PacketBuilder)
				if !ok {
					log.Debug().Msg("Not a PacketBuilder")
				}
				nextDecoder := newipv4.NextLayerType()
				_ = nextDecoder.Decode(newipv4.Payload, pb)
			}
		}

		packets <- TcpPacketInfo{
			Packet: packet,
			Source: source,
		}
	}
}
