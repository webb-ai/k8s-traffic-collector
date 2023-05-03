package assemblers

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/kubeshark/gopacket"
	"github.com/kubeshark/gopacket/layers"
	"github.com/kubeshark/gopacket/pcapgo"
	"github.com/kubeshark/gopacket/reassembly"
	"github.com/kubeshark/worker/diagnose"
	"github.com/kubeshark/worker/misc"
	"github.com/kubeshark/worker/misc/wcap"
	"github.com/kubeshark/worker/pkg/api"
	"github.com/kubeshark/worker/source"
	"github.com/kubeshark/worker/vm"
	"github.com/rs/zerolog/log"
)

type AssemblerMode int

const (
	MasterCapture AssemblerMode = iota
	SortCapture
	ItemCapture
)

const (
	lastClosedConnectionsMaxItems = 1000
	packetsSeenLogThreshold       = 1000
	lastAckThreshold              = time.Duration(3) * time.Second
)

type AssemblerStats struct {
	FlushedConnections int
	ClosedConnections  int
}

type MasterPcap struct {
	file   *os.File
	writer *pcapgo.Writer
	sync.Mutex
}

func (m *MasterPcap) WritePacket(ci gopacket.CaptureInfo, data []byte) (err error) {
	m.Lock()
	err = m.writer.WritePacket(ci, data)
	m.Unlock()
	return
}

type TcpAssembler struct {
	*reassembly.Assembler
	captureMode            AssemblerMode
	masterPcap             *MasterPcap
	sortedPackets          chan<- *wcap.SortedPacket
	streamPool             *reassembly.StreamPool
	streamFactory          *tcpStreamFactory
	dnsFactory             *dnsFactory
	staleConnectionTimeout time.Duration
	stats                  AssemblerStats
	sync.Mutex
}

// Context
// The assembler context
type context struct {
	CaptureInfo gopacket.CaptureInfo
}

func (c *context) GetCaptureInfo() gopacket.CaptureInfo {
	return c.CaptureInfo
}

func NewTcpAssembler(
	pcapId string,
	captureMode AssemblerMode,
	sortedPackets chan<- *wcap.SortedPacket,
	outputChannel chan *api.OutputChannelItem,
	streamsMap api.TcpStreamMap,
	opts *misc.Opts,
) *TcpAssembler {
	a := &TcpAssembler{
		captureMode:            captureMode,
		sortedPackets:          sortedPackets,
		staleConnectionTimeout: opts.StaleConnectionTimeout,
		stats:                  AssemblerStats{},
	}

	if a.captureMode == MasterCapture {
		a.initMasterPcap()
		go a.limitMasterPcapSize(misc.GetMasterPcapSizeLimit())
	}

	a.streamFactory = NewTcpStreamFactory(
		pcapId,
		a,
		outputChannel,
		streamsMap,
		opts,
	)
	a.streamPool = reassembly.NewStreamPool(a.streamFactory)
	a.Assembler = reassembly.NewAssembler(a.streamPool)

	a.dnsFactory = NewDnsFactory(
		pcapId,
		a,
		outputChannel,
		streamsMap,
		opts,
	)

	maxBufferedPagesTotal := GetMaxBufferedPagesPerConnection()
	maxBufferedPagesPerConnection := GetMaxBufferedPagesTotal()
	log.Debug().
		Int("maxBufferedPagesTotal", maxBufferedPagesTotal).
		Int("maxBufferedPagesPerConnection", maxBufferedPagesPerConnection).
		Interface("opts", opts).
		Msg("Assembler options:")
	a.Assembler.AssemblerOptions.MaxBufferedPagesTotal = maxBufferedPagesTotal
	a.Assembler.AssemblerOptions.MaxBufferedPagesPerConnection = maxBufferedPagesPerConnection

	return a
}

func (a *TcpAssembler) initMasterPcap() {
	var err error
	var file *os.File
	var writer *pcapgo.Writer
	if _, err = os.Stat(misc.GetMasterPcapPath()); errors.Is(err, os.ErrNotExist) {
		file, err = os.OpenFile(misc.GetMasterPcapPath(), os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Error().Err(err).Msg("Couldn't create master PCAP:")
		} else {
			writer = pcapgo.NewWriter(file)
			a.masterPcap = &MasterPcap{
				file:   file,
				writer: writer,
			}
			err = writer.WriteFileHeader(uint32(misc.Snaplen), layers.LinkTypeEthernet)
			if err != nil {
				log.Error().Err(err).Msg("While writing the PCAP header:")
			}
		}
	} else {
		file, err = os.OpenFile(misc.GetMasterPcapPath(), os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			log.Error().Err(err).Msg("Couldn't open master PCAP:")
		} else {
			writer = pcapgo.NewWriter(file)
			a.masterPcap = &MasterPcap{
				file:   file,
				writer: writer,
			}
		}
	}
}

func (a *TcpAssembler) resetMasterPcap() {
	var err error
	a.masterPcap.file, err = os.OpenFile(misc.GetMasterPcapPath(), os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		log.Error().Err(err).Msg("Couldn't open master PCAP:")
	} else {
		a.masterPcap.writer = pcapgo.NewWriter(a.masterPcap.file)
		err = a.masterPcap.writer.WriteFileHeader(uint32(misc.Snaplen), layers.LinkTypeEthernet)
		if err != nil {
			log.Error().Err(err).Msg("While writing the PCAP header:")
		}

		defaultContext := misc.GetContextPath(misc.DefaultContext)
		err = os.RemoveAll(defaultContext)
		if err != nil {
			log.Error().Err(err).Send()
		} else {
			err = os.MkdirAll(defaultContext, os.ModePerm)
			if err != nil {
				return
			}
		}
	}
}

func (a *TcpAssembler) limitMasterPcapSize(limit int64) {
	for range time.Tick(misc.MasterPcapSizeCheckPeriod) {
		info, err := os.Stat(misc.GetMasterPcapPath())
		if err != nil {
			log.Error().Err(err).Send()
			continue
		}

		if info.Size() > limit {
			a.resetMasterPcap()
		}
	}
}

func (a *TcpAssembler) SendSortedPacket(sortedPacket *wcap.SortedPacket) {
	// SortCapture or (MasterCapture and there is a script)
	if a.captureMode == SortCapture || (a.captureMode == MasterCapture && vm.Len() > 0) {
		a.sortedPackets <- sortedPacket
	}
}

func (a *TcpAssembler) ProcessPackets(packets <-chan source.TcpPacketInfo) {
	ticker := time.NewTicker(5 * time.Second)
	dumpPacket := false

	for {
		select {
		case packetInfo, ok := <-packets:
			if !ok {
				if a.sortedPackets != nil {
					close(a.sortedPackets)
				}
				return
			}
			a.ProcessPacket(packetInfo, dumpPacket)
		case <-ticker.C:
			a.PeriodicClean()
		}
	}
}

func (a *TcpAssembler) ProcessPacket(packetInfo source.TcpPacketInfo, dumpPacket bool) {
	packetsCount := diagnose.AppStats.IncPacketsCount()

	if packetsCount%packetsSeenLogThreshold == 0 {
		log.Debug().Int("count", int(packetsCount)).Msg("Packets seen:")
	}

	packet := packetInfo.Packet
	data := packet.Data()
	diagnose.AppStats.UpdateProcessedBytes(uint64(len(data)))
	if dumpPacket {
		log.Debug().Msg(fmt.Sprintf("Packet content (%d/0x%x) - %s", len(data), len(data), hex.Dump(data)))
	}

	tcp := packet.Layer(layers.LayerTypeTCP)
	if tcp != nil {
		a.processTCPPacket(packet, tcp.(*layers.TCP))
	}

	dns := packet.Layer(layers.LayerTypeDNS)
	if dns != nil {
		a.processDNSPacket(packet, dns.(*layers.DNS))
	}
}

func (a *TcpAssembler) processTCPPacket(packet gopacket.Packet, tcp *layers.TCP) {
	diagnose.AppStats.IncTcpPacketsCount()

	c := context{
		CaptureInfo: packet.Metadata().CaptureInfo,
	}
	a.AssembleWithContext(packet, tcp, &c)
}

func (a *TcpAssembler) processDNSPacket(packet gopacket.Packet, dns *layers.DNS) {
	diagnose.AppStats.IncDnsPacketsCount()

	a.dnsFactory.handlePacket(packet, dns.ID)
	a.dnsFactory.emitItem(packet, dns)
}

func (a *TcpAssembler) DumpStreamPool() {
	a.streamPool.Dump()
}

func (a *TcpAssembler) WaitAndDump() {
	log.Debug().Msg(a.Dump())
}

func (a *TcpAssembler) PeriodicClean() {
	a.Lock()
	flushed, closed := a.FlushCloseOlderThan(time.Now().Add(-a.staleConnectionTimeout))
	stats := a.stats
	stats.ClosedConnections += closed
	stats.FlushedConnections += flushed
	a.Unlock()
}

func (a *TcpAssembler) DumpStats() AssemblerStats {
	a.Lock()
	result := a.stats
	a.stats = AssemblerStats{}
	a.Unlock()
	return result
}

func (a *TcpAssembler) GetMasterPcap() *MasterPcap {
	return a.masterPcap
}
