package mergecap

import (
	"bufio"
	"container/heap"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/kubeshark/gopacket/layers"
	"github.com/kubeshark/gopacket/pcapgo"
	"github.com/kubeshark/worker/misc"
	"github.com/kubeshark/worker/misc/mergecap/minheap"
	"github.com/rs/zerolog/log"
)

const maxSnaplen uint32 = 262144

// previousTimestamp is the timestamp of the previous packet popped from the heap.
// It helps us find bad/corrupted packets with weird timestamps.
var previousTimestamp int64

func Mergecap(pcapFiles []fs.DirEntry, query string, selectedPcaps []string, outFile *os.File) error {
	// Init a minimum heap by packet timestamp
	minTimeHeap := minheap.PacketHeap{}
	heap.Init(&minTimeHeap)

	linkType := initHeapWithPcapFiles(pcapFiles, query, selectedPcaps, &minTimeHeap)

	// Init the output file
	bufferedFileWriter := bufio.NewWriter(outFile)
	defer bufferedFileWriter.Flush()

	writer := pcapgo.NewWriter(bufferedFileWriter)
	err := writer.WriteFileHeader(maxSnaplen, linkType)
	if err != nil {
		return err
	}

	// Main loop
	for minTimeHeap.Len() > 0 {
		// Find the earliest packet and write it to the output file
		earliestPacket := heap.Pop(&minTimeHeap).(minheap.Packet)
		write(writer, earliestPacket)

		var earliestHeapTime int64
		if minTimeHeap.Len() > 0 {
			earliestHeapTime = minTimeHeap[0].Timestamp
		}
		for {
			// Read the next packet from the source of the last written packet
			nextPacket, err := readNext(
				earliestPacket.Reader,
				earliestPacket.InputFile,
				false)
			if err == io.EOF {
				// Done with this source
				break
			}

			if nextPacket.Timestamp <= earliestHeapTime {
				// This is the earliest packet, write it to the output file
				// (Skip pushing it to the heap. This is much faster)
				write(writer, nextPacket)
				continue
			}

			// This is not the earliest packet, push it to the heap for sorting
			heap.Push(&minTimeHeap, nextPacket)
			break
		}
	}

	return nil
}

// initHeapWithPcapFiles inits minTimeHeap with one packet from each source file.
// It also returns the output LinkType, which is decided by the LinkTypes of all of the
// input files.
func initHeapWithPcapFiles(pcapFiles []fs.DirEntry, query string, selectedPcaps []string, minTimeHeap *minheap.PacketHeap) layers.LinkType {
	var totalInputSizeBytes int64
	var linkType layers.LinkType

	for _, pcap := range pcapFiles {
		if filepath.Ext(pcap.Name()) != ".pcap" {
			continue
		}

		if query != "" && !misc.Contains(selectedPcaps, pcap.Name()) {
			continue
		}

		// Read the first packet and push it to the heap
		inputFile, err := os.Open(fmt.Sprintf("%s/%s", misc.GetPcapsDir(), pcap.Name()))
		if err != nil {
			log.Error().Err(err).Str("pcap", pcap.Name()).Msg("(Mergecap) Skipping PCAP file:")
			continue
		}

		reader, err := pcapgo.NewReader(inputFile)
		if err != nil {
			log.Error().Err(err).Str("pcap", inputFile.Name()).Msg("(Mergecap) Skipping PCAP file:")
			continue
		}

		fStat, _ := inputFile.Stat()
		totalInputSizeBytes += fStat.Size()

		reader.SetSnaplen(maxSnaplen)
		if linkType == layers.LinkTypeNull {
			// Init
			linkType = reader.LinkType()
		} else if linkType != reader.LinkType() {
			// Conflicting input LinkTypes. Use default type of Ethernet.
			linkType = layers.LinkTypeEthernet
		}

		nextPacket, err := readNext(reader, inputFile, true)
		if err != nil {
			log.Error().Err(err).Str("pcap", inputFile.Name()).Msg("(Mergecap) Skipping PCAP file:")
			continue
		}

		heap.Push(minTimeHeap, nextPacket)

		// Init previousTimestamp
		if previousTimestamp == 0 {
			previousTimestamp = nextPacket.Timestamp
		} else if nextPacket.Timestamp < previousTimestamp {
			previousTimestamp = nextPacket.Timestamp
		}
	}

	return linkType
}

func readNext(reader *pcapgo.Reader, inputFile *os.File, isInit bool) (minheap.Packet, error) {
	for {
		data, captureInfo, err := reader.ZeroCopyReadPacketData()
		if err != nil {
			if err == io.EOF {
				// Done with this source
				inputFile.Close()

				return minheap.Packet{}, io.EOF
			}
			// Skip errors
			continue
		}

		timestamp := captureInfo.Timestamp.UnixNano()
		oneHour := int64(time.Nanosecond * time.Hour)

		if !isInit && timestamp+oneHour < previousTimestamp {
			// Skip errors
			continue
		}
		if len(data) == 0 {
			// Skip errors
			continue
		}

		return minheap.Packet{
			Timestamp:   timestamp,
			CaptureInfo: captureInfo,
			Data:        data,
			Reader:      reader,
			InputFile:   inputFile,
		}, nil
	}
}

func write(writer *pcapgo.Writer, packetToWrite minheap.Packet) {
	err := writer.WritePacket(packetToWrite.CaptureInfo, packetToWrite.Data)
	if err != nil {
		// Skip errors
		log.Debug().Err(err).Msg("(Mergecap) Skipping this packet:")
	}

	previousTimestamp = packetToWrite.Timestamp
}
