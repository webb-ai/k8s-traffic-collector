package assemblers

import (
	"encoding/hex"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/kubeshark/gopacket"
	"github.com/kubeshark/gopacket/layers"
	"github.com/kubeshark/gopacket/reassembly"
	"github.com/kubeshark/worker/diagnose"
	"github.com/kubeshark/worker/misc"
	"github.com/kubeshark/worker/pkg/api"
	"github.com/kubeshark/worker/source"
	"github.com/rs/zerolog/log"
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

type TcpAssembler struct {
	*reassembly.Assembler
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

func NewTcpAssembler(pcapId string, identifyMode bool, outputChannel chan *api.OutputChannelItem, streamsMap api.TcpStreamMap, opts *misc.Opts) *TcpAssembler {
	a := &TcpAssembler{
		staleConnectionTimeout: opts.StaleConnectionTimeout,
		stats:                  AssemblerStats{},
	}

	a.streamFactory = NewTcpStreamFactory(pcapId, identifyMode, outputChannel, streamsMap, opts)
	a.streamPool = reassembly.NewStreamPool(a.streamFactory)
	a.Assembler = reassembly.NewAssembler(a.streamPool)

	a.dnsFactory = NewDnsFactory(pcapId, identifyMode, outputChannel, streamsMap, opts)

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

func (a *TcpAssembler) ProcessPackets(packets <-chan source.TcpPacketInfo) {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt)
	ticker := time.NewTicker(a.staleConnectionTimeout)
	dumpPacket := false

	for {
		select {
		case packetInfo, ok := <-packets:
			if !ok {
				break
			}
			a.ProcessPacket(packetInfo, dumpPacket)
		case <-signalChan:
			log.Info().Msg("Caught SIGINT: aborting")
			break
		case <-ticker.C:
			a.periodicClean()
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

	a.dnsFactory.writePacket(packet, dns.ID)
	a.dnsFactory.emitItem(packet, dns)
}

func (a *TcpAssembler) DumpStreamPool() {
	a.streamPool.Dump()
}

func (a *TcpAssembler) WaitAndDump() {
	log.Debug().Msg(a.Dump())
}

func (a *TcpAssembler) periodicClean() {
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
