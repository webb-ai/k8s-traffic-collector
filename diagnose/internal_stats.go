package diagnose

import "log"

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
	log.Printf("IPdefrag:\t\t%d", stats.Ipdefrag)
	log.Printf("TCP stats:")
	log.Printf(" missed bytes:\t\t%d", stats.MissedBytes)
	log.Printf(" total packets:\t\t%d", stats.Pkt)
	log.Printf(" rejected FSM:\t\t%d", stats.RejectFsm)
	log.Printf(" rejected Options:\t%d", stats.RejectOpt)
	log.Printf(" reassembled bytes:\t%d", stats.Sz)
	log.Printf(" total TCP bytes:\t%d", stats.Totalsz)
	log.Printf(" conn rejected FSM:\t%d", stats.RejectConnFsm)
	log.Printf(" reassembled chunks:\t%d", stats.Reassembled)
	log.Printf(" out-of-order packets:\t%d", stats.OutOfOrderPackets)
	log.Printf(" out-of-order bytes:\t%d", stats.OutOfOrderBytes)
	log.Printf(" biggest-chunk packets:\t%d", stats.BiggestChunkPackets)
	log.Printf(" biggest-chunk bytes:\t%d", stats.BiggestChunkBytes)
	log.Printf(" overlap packets:\t%d", stats.OverlapPackets)
	log.Printf(" overlap bytes:\t\t%d", stats.OverlapBytes)
}
