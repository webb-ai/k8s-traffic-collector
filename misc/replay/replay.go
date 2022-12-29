package replay

import (
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/kubeshark/gopacket"
	"github.com/kubeshark/gopacket/layers"
	"github.com/kubeshark/gopacket/pcapgo"
	"github.com/rs/zerolog/log"
)

const ignoringPacketMsg string = "Ignoring packet:"

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

func replay(pcapPath string, host string, port string, delay uint64) error {
	f, err := os.Open(pcapPath)
	if err != nil {
		return err
	}
	defer f.Close()

	packets := make(chan gopacket.Packet)
	defer close(packets)

	reader, err := pcapgo.NewReader(f)
	if err != nil {
		return err
	}

	log.Debug().Str("host", host).Str("port", port).Msg("Establishing a new TCP connection...")

	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%s", host, port))
	if err != nil {
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

			// TCP layer
			tcpLayer := packet.Layer(layers.LayerTypeTCP)
			if tcpLayer == nil {
				log.Debug().Str("reason", "Missing TCP layer").Msg(ignoringPacketMsg)
				continue
			}
			dstPort = fmt.Sprintf("%d", tcpLayer.(*layers.TCP).DstPort)

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

	err = sendPerPacket(reader, packets, time.Duration(delay)*time.Microsecond)
	if err != nil {
		log.Error().Err(err).Msg("Replay send packet error:")
		return err
	}

	return nil
}

func Replay(pcapPath string, host string, port string, count uint64, delay uint64) error {
	for count > 0 {
		log.Debug().Int("countdown", int(count)).Str("pcap", pcapPath).Msg("Replaying PCAP:")
		count--

		err := replay(pcapPath, host, port, delay)
		if err != nil {
			return err
		}
	}

	return nil
}
