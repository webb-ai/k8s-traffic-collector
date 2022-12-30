package diagnose

import (
	"fmt"
	"os"
	"runtime"
	"runtime/pprof"
	"strconv"
	"time"

	"github.com/kubeshark/base/pkg/api"
	"github.com/rs/zerolog/log"
)

var AppStats = api.AppStats{}

func StartMemoryProfiler(envDumpPath string, envTimeInterval string) {
	dumpPath := "/app/pprof"
	if envDumpPath != "" {
		dumpPath = envDumpPath
	}
	timeInterval := 60
	if envTimeInterval != "" {
		if i, err := strconv.Atoi(envTimeInterval); err == nil {
			timeInterval = i
		}
	}

	log.Info().Str("path", dumpPath).Msg("Profiling is on, results will be written to:")
	go func() {
		if _, err := os.Stat(dumpPath); os.IsNotExist(err) {
			if err := os.Mkdir(dumpPath, 0777); err != nil {
				log.Fatal().Err(err).Msg("Couldn't create directory for the profile!")
			}
		}

		for {
			t := time.Now()

			filename := fmt.Sprintf("%s/%s__mem.prof", dumpPath, t.Format(time.RFC3339))

			log.Info().Str("file", filename).Msg("Writing memory profile to:")

			f, err := os.Create(filename)
			if err != nil {
				log.Fatal().Err(err).Msg("Couldn't create memory profile!")
			}
			runtime.GC() // get up-to-date statistics
			if err := pprof.WriteHeapProfile(f); err != nil {
				log.Fatal().Err(err).Msg("Couldn't create memory profile!")
			}
			_ = f.Close()
			time.Sleep(time.Second * time.Duration(timeInterval))
		}
	}()
}

func DumpMemoryProfile(filename string) error {
	if filename == "" {
		return nil
	}

	f, err := os.Create(filename)

	if err != nil {
		return err
	}

	defer f.Close()

	if err := pprof.WriteHeapProfile(f); err != nil {
		return err
	}

	return nil
}
