package diagnose

import (
	"fmt"

	"github.com/rs/zerolog/log"
)

type workerInternalStats struct {
	Ipdefrag            int
	MissedBytes         int
	Pkt                 int
	Sz                  int
	Totalsz             int
	RejectFsm           int
	RejectOpt           int
	RejectConnFsm       int
	Reassembled         int
	OutOfOrderBytes     int
	OutOfOrderPackets   int
	BiggestChunkBytes   int
	BiggestChunkPackets int
	OverlapBytes        int
	OverlapPackets      int
}

var InternalStats *workerInternalStats

func InitializeWorkerInternalStats() {
	InternalStats = &workerInternalStats{}
}

func (stats *workerInternalStats) PrintStatsSummary() {
	log.Info().Msg(fmt.Sprintf("IPdefrag:\t\t%d", stats.Ipdefrag))
	log.Info().Msg("TCP stats:")
	log.Info().Msg(fmt.Sprintf(" missed bytes:\t\t%d", stats.MissedBytes))
	log.Info().Msg(fmt.Sprintf(" total packets:\t\t%d", stats.Pkt))
	log.Info().Msg(fmt.Sprintf(" rejected FSM:\t\t%d", stats.RejectFsm))
	log.Info().Msg(fmt.Sprintf(" rejected Options:\t%d", stats.RejectOpt))
	log.Info().Msg(fmt.Sprintf(" reassembled bytes:\t%d", stats.Sz))
	log.Info().Msg(fmt.Sprintf(" total TCP bytes:\t%d", stats.Totalsz))
	log.Info().Msg(fmt.Sprintf(" conn rejected FSM:\t%d", stats.RejectConnFsm))
	log.Info().Msg(fmt.Sprintf(" reassembled chunks:\t%d", stats.Reassembled))
	log.Info().Msg(fmt.Sprintf(" out-of-order packets:\t%d", stats.OutOfOrderPackets))
	log.Info().Msg(fmt.Sprintf(" out-of-order bytes:\t%d", stats.OutOfOrderBytes))
	log.Info().Msg(fmt.Sprintf(" biggest-chunk packets:\t%d", stats.BiggestChunkPackets))
	log.Info().Msg(fmt.Sprintf(" biggest-chunk bytes:\t%d", stats.BiggestChunkBytes))
	log.Info().Msg(fmt.Sprintf(" overlap packets:\t%d", stats.OverlapPackets))
	log.Info().Msg(fmt.Sprintf(" overlap bytes:\t\t%d", stats.OverlapBytes))
}
