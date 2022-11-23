package diagnose

import (
	"fmt"
	"log"
	"os"
	"runtime"
	"runtime/pprof"
	"strconv"
	"time"

	"github.com/kubeshark/worker/api"
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

	log.Printf("Profiling is on, results will be written to %s", dumpPath)
	go func() {
		if _, err := os.Stat(dumpPath); os.IsNotExist(err) {
			if err := os.Mkdir(dumpPath, 0777); err != nil {
				log.Fatal("could not create directory for profile: ", err)
			}
		}

		for {
			t := time.Now()

			filename := fmt.Sprintf("%s/%s__mem.prof", dumpPath, t.Format("15_04_05"))

			log.Printf("Writing memory profile to %s", filename)

			f, err := os.Create(filename)
			if err != nil {
				log.Fatal("could not create memory profile: ", err)
			}
			runtime.GC() // get up-to-date statistics
			if err := pprof.WriteHeapProfile(f); err != nil {
				log.Fatal("could not write memory profile: ", err)
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
