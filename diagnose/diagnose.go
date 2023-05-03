package diagnose

import (
	"fmt"
	"os"
	"runtime"
	"runtime/pprof"
	"strconv"
	"time"

	"github.com/kubeshark/worker/pkg/api"
	"github.com/rs/zerolog/log"
)

var AppStats = api.AppStats{}

func StartProfiler(envDumpPath string, envTimeInterval string) {
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

	if _, err := os.Stat(dumpPath); os.IsNotExist(err) {
		if err := os.Mkdir(dumpPath, 0777); err != nil {
			log.Fatal().Err(err).Msg("Couldn't create directory for the profile!")
			return
		}
	}

	log.Info().Str("path", dumpPath).Msg("Profiling is on, results will be written to:")
	cpuFilename := fmt.Sprintf("%s/cpu.prof", dumpPath)

	log.Info().Str("file", cpuFilename).Msg("Writing CPU profile to:")

	cpuFile, err := os.Create(cpuFilename)
	if err != nil {
		log.Fatal().Err(err).Msg("Couldn't create CPU profile!")
	}
	if err := pprof.StartCPUProfile(cpuFile); err != nil {
		log.Fatal().Err(err).Msg("Couldn't create CPU profile!")
	}

	for {
		t := time.Now()

		memoryFilename := fmt.Sprintf("%s/%s__mem.prof", dumpPath, t.Format(time.RFC3339))

		log.Info().Str("file", memoryFilename).Msg("Writing memory profile to:")

		memoryFile, err := os.Create(memoryFilename)
		if err != nil {
			log.Fatal().Err(err).Msg("Couldn't create memory profile!")
		}
		runtime.GC() // get up-to-date statistics
		if err := pprof.WriteHeapProfile(memoryFile); err != nil {
			log.Fatal().Err(err).Msg("Couldn't create memory profile!")
		}
		_ = memoryFile.Close()
		time.Sleep(time.Second * time.Duration(timeInterval))
	}
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
