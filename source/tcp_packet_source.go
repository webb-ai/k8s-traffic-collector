package source

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/kubeshark/gopacket"
	"github.com/kubeshark/gopacket/ip4defrag"
	"github.com/kubeshark/gopacket/layers"
	"github.com/kubeshark/worker/misc"
	"github.com/kubeshark/worker/misc/wcap"
	"github.com/kubeshark/worker/vm"
	"github.com/rs/zerolog/log"
)

type Handle interface {
	NextPacket() (packet gopacket.Packet, err error)
	SetDecoder(decoder gopacket.Decoder, lazy bool, noCopy bool)
	SetBPF(expr string) (err error)
	LinkType() layers.LinkType
	Stats() (packetsReceived uint, packetsDropped uint, err error)
	Close() (err error)
	FileSize() (size int64, err error)
}

type TcpPacketSource struct {
	Handle        Handle
	defragger     *ip4defrag.IPv4Defragmenter
	name          string
	filename      string
	interfaceName string
	targetSizeMb  int
	promisc       bool
	tstype        string
	lazy          bool
}

type TcpPacketInfo struct {
	Packet gopacket.Packet
	Source *TcpPacketSource
}

func NewTcpPacketSource(name, filename string, interfaceName string, packetCapture string) (*TcpPacketSource, error) {
	var err error

	source := &TcpPacketSource{
		defragger:     ip4defrag.NewIPv4Defragmenter(),
		name:          name,
		filename:      filename,
		interfaceName: interfaceName,
		targetSizeMb:  8,
		promisc:       true,
		tstype:        "",
		lazy:          false,
	}

	switch packetCapture {
	case "af_packet":
		source.Handle, err = newAfpacketHandle(
			source.interfaceName,
			source.targetSizeMb,
			misc.Snaplen,
		)
		if err != nil {
			return nil, err
		}
		log.Debug().Msg("Using AF_PACKET socket as the capture source")
	default:
		err = source.NewPcapHandle()
		if err != nil {
			return nil, err
		}
		log.Debug().Msg("Using libpcap as the capture source")
	}

	if filename == "" {
		var decoder gopacket.Decoder
		var ok bool
		decoderName := source.Handle.LinkType().String()
		if decoder, ok = gopacket.DecodersByLayerName[decoderName]; !ok {
			source.Handle.Close()
			return nil, fmt.Errorf("no decoder named %v", decoderName)
		}

		source.Handle.SetDecoder(decoder, source.lazy, true)
	}

	return source, nil
}

func (source *TcpPacketSource) NewPcapHandle() error {
	var err error
	source.Handle, err = newPcapHandle(
		source.filename,
		source.interfaceName,
		misc.Snaplen,
		source.promisc,
		source.tstype,
	)

	return err
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

func (source *TcpPacketSource) ReadPackets(
	packets chan<- TcpPacketInfo,
	dontClose bool,
	masterCapture bool,
	sortedPackets chan<- *wcap.SortedPacket,
) {
	log.Debug().Str("source", source.name).Msg("Start reading packets from:")

	var previousSize int64

	for {
		packet, err := source.Handle.NextPacket()

		if err == io.EOF {
			if dontClose {
				time.Sleep(100 * time.Millisecond)

				size, err := source.Handle.FileSize()
				if err != nil {
					log.Debug().Err(err).Send()
					return
				}

				// This means `resetMasterPcap` is called and
				// the `master.pcap` file is truncated
				if previousSize > size {
					err = source.NewPcapHandle()
					if err != nil {
						log.Debug().Err(err).Send()
						return
					}
				}
				previousSize = size
				continue
			}

			log.Debug().Str("source", source.name).Msg("Got EOF while reading packets from:")
			return
		} else if err != nil {
			if strings.HasSuffix(err.Error(), "file already closed") {
				log.Debug().Str("source", source.name).Msg("PCAP file is closed.")
				close(packets)
				return
			}
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
				if masterCapture {
					vm.PacketCapturedHook(packet, false)
				}
				continue
			} else if newipv4 == nil {
				log.Debug().Msg("Fragment...")
				if masterCapture {
					vm.PacketCapturedHook(packet, true)
				}
				continue // packet fragment, we don't have whole packet yet.
			}
			if newipv4.Length != l {
				log.Debug().Int("layer-type", int(newipv4.NextLayerType())).Msg("Decoding re-assembled packet:")
				pb, ok := packet.(gopacket.PacketBuilder)
				if !ok {
					log.Debug().Msg("Not a PacketBuilder")
				}
				nextDecoder := newipv4.NextLayerType()
				_ = nextDecoder.Decode(newipv4.Payload, pb)
			}
		}

		if masterCapture {
			vm.PacketCapturedHook(packet, false)
		}

		packets <- TcpPacketInfo{
			Packet: packet,
			Source: source,
		}
	}
}
