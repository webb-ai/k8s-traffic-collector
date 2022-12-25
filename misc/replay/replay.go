package replay

import (
	"io"
	"os"
	"time"

	"github.com/kubeshark/gopacket/pcap"
	"github.com/kubeshark/gopacket/pcapgo"
	"github.com/rs/zerolog/log"
)

func sendPerPacket(reader *pcapgo.Reader, packets chan<- []byte, delayGrace time.Duration) error {
	defer close(packets)
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
		packets <- data
	}

	return nil
}

func Replay(pcapPath string, iface string, count uint64, delay uint64) error {
	f, err := os.Open(pcapPath)
	if err != nil {
		return err
	}
	defer f.Close()

	packets := make(chan []byte)

	reader, err := pcapgo.NewReader(f)
	if err != nil {
		return err
	}

	writer, err := pcap.OpenLive(iface, 65536, true, pcap.BlockForever)
	if err != nil {
		return err
	}
	defer writer.Close()

	go func() {
		for packet := range packets {
			if err := writer.WritePacketData(packet); err != nil {
				log.Error().Err(err).Msg("Replay write packet error:")
				break
			}
		}
	}()

	for count > 0 {
		count--
		err = sendPerPacket(reader, packets, time.Duration(delay)*time.Microsecond)
		if err != nil {
			log.Error().Err(err).Msg("Replay send packet error:")
			break
		}
	}

	return nil
}
