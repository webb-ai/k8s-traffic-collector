package replay

import (
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kubeshark/gopacket"
	"github.com/kubeshark/gopacket/layers"
	"github.com/kubeshark/gopacket/pcapgo"
	"github.com/kubeshark/worker/misc"
	"github.com/rs/zerolog/log"
)

const ignoringPacketMsg string = "Ignoring packet:"

type StreamType string

const (
	TCP StreamType = "tcp"
	UDP StreamType = "udp"
)

func sendPerPacket(reader *pcapgo.Reader, packets chan<- gopacket.Packet, delayGrace time.Duration) error {
	var last time.Time

	for {
		data, ci, err := reader.ReadPacketData()

		if err != nil {
			if err == io.EOF {
				break
			} else {
				return err
			}
		}

		if !last.IsZero() {
			delay := ci.Timestamp.Sub(last)
			if delay > delayGrace && !ci.Timestamp.Before(last) {
				time.Sleep(delay)
			}
		}

		packets <- gopacket.NewPacket(data, layers.LinkTypeEthernet, gopacket.Lazy)
	}

	return nil
}

func replay(pcapPath string, host string, port string, delayGrace time.Duration) error {
	f, err := os.Open(pcapPath)
	if err != nil {
		log.Error().Err(err).Send()
		return err
	}
	defer f.Close()

	packets := make(chan gopacket.Packet, misc.PacketChannelBufferSize)
	defer close(packets)

	reader, err := pcapgo.NewReader(f)
	if err != nil {
		log.Error().Err(err).Send()
		return err
	}

	var streamType = TCP
	if strings.HasSuffix(pcapPath[:len(pcapPath)-len(filepath.Ext(pcapPath))], "_udp") {
		streamType = UDP
	}

	log.Debug().Str("host", host).Str("port", port).Msg(fmt.Sprintf("Establishing a new %s connection...", strings.ToUpper(string(streamType))))

	conn, err := net.Dial(string(streamType), fmt.Sprintf("%s:%s", host, port))
	if err != nil {
		log.Error().Err(err).Send()
		return err
	}

	go func() {
		for packet := range packets {
			// IPv4 layer
			var dstHost, dstPort string
			ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
			if ipv4Layer != nil {
				dstHost = ipv4Layer.(*layers.IPv4).DstIP.String()
			}

			// IPv6 layer
			ipv6Layer := packet.Layer(layers.LayerTypeIPv6)
			if ipv6Layer != nil {
				dstHost = ipv6Layer.(*layers.IPv6).DstIP.String()
			}

			if ipv4Layer == nil && ipv6Layer == nil {
				log.Debug().Str("reason", "Missing IPv4/IPv6 layer").Msg(ignoringPacketMsg)
				continue
			}

			switch streamType {
			case TCP:
				// TCP layer
				tcpLayer := packet.Layer(layers.LayerTypeTCP)
				if tcpLayer == nil {
					log.Debug().Str(
						"reason",
						fmt.Sprintf("Missing %s layer", strings.ToUpper(string(streamType))),
					).Msg(ignoringPacketMsg)
					continue
				}
				dstPort = fmt.Sprintf("%d", tcpLayer.(*layers.TCP).DstPort)
			case UDP:
				// UDP layer
				udpLayer := packet.Layer(layers.LayerTypeUDP)
				if udpLayer == nil {
					log.Debug().Str(
						"reason",
						fmt.Sprintf("Missing %s layer", strings.ToUpper(string(streamType))),
					).Msg(ignoringPacketMsg)
					continue
				}
				dstPort = fmt.Sprintf("%d", udpLayer.(*layers.UDP).DstPort)
			default:
				continue
			}

			if dstHost != host || dstPort != port {
				log.Debug().Str("dst-host", dstHost).Str("dst-port", dstPort).Msg(ignoringPacketMsg)
				continue
			}

			var payload []byte
			applicationLayer := packet.ApplicationLayer()
			if applicationLayer == nil {
				log.Debug().Str("reason", "Missing application layer").Msg(ignoringPacketMsg)
				continue
			}
			payload = applicationLayer.Payload()

			log.Debug().Str("dst-host", dstHost).Str("dst-port", dstPort).Str("payload", string(payload)).Msg("Writing packet:")

			if err := conn.SetWriteDeadline(time.Now().Add(1 * time.Second)); err != nil {
				log.Error().Err(err).Send()
			}

			if _, err := conn.Write(payload); err != nil {
				log.Error().Err(err).Msg("Replay write packet error:")
				break
			}
		}
	}()

	err = sendPerPacket(reader, packets, delayGrace)
	if err != nil {
		log.Error().Err(err).Msg("Replay send packet error:")
		return err
	}

	return nil
}

func Replay(pcapPath string, host string, port string, count uint64, delay uint64, concurrency bool) error {
	delayGrace := time.Duration(delay) * time.Microsecond
	for count > 0 {
		log.Debug().Int("countdown", int(count)).Str("pcap", pcapPath).Msg("Replaying PCAP:")
		count--

		if concurrency {
			go replay(pcapPath, host, port, delayGrace) //nolint

			if count > 0 {
				time.Sleep(delayGrace)
			}
		} else {
			err := replay(pcapPath, host, port, delayGrace)
			if err != nil {
				return err
			}
		}
	}

	return nil
}
