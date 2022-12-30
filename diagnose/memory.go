package diagnose

import (
	"fmt"
	"runtime"
	"strconv"
	"time"

	"github.com/rs/zerolog/log"
)

func bToMb(b uint64) uint64 {
	return b / 1024 / 1024
}

func printMemUsage(memoryUsageTimeInterval string) {
	timeInterval := 500
	if memoryUsageTimeInterval != "" {
		if i, err := strconv.Atoi(memoryUsageTimeInterval); err == nil {
			timeInterval = i
		}
	}

	for range time.Tick(time.Millisecond * time.Duration(timeInterval)) {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)

		log.Debug().
			Int("num-goroutines", runtime.NumGoroutine()).
			Str("alloc", fmt.Sprintf("%v MiB", bToMb(m.Alloc))).
			Str("total-alloc", fmt.Sprintf("%v MiB", bToMb(m.TotalAlloc))).
			Str("sys", fmt.Sprintf("%v MiB", bToMb(m.Sys))).
			Int("gc-cycles", int(m.NumGC)).
			Send()
	}
}
