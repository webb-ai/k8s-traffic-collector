package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/docker/go-units"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/kubeshark/worker/assemblers"
	"github.com/kubeshark/worker/diagnose"
	"github.com/kubeshark/worker/misc"
	"github.com/kubeshark/worker/misc/wcap"
	"github.com/kubeshark/worker/pkg/api"
	"github.com/kubeshark/worker/queue"
	"github.com/kubeshark/worker/source"
	"github.com/kubeshark/worker/target"
	"github.com/kubeshark/worker/tracer"
	"github.com/rs/zerolog/log"
	"github.com/shirou/gopsutil/cpu"
	"github.com/struCoder/pidusage"
)

const cleanPeriod = time.Second * 10

var table1 []table.Row
var table2 []table.Row
var table3 []table.Row

func startWorker(opts *misc.Opts, streamsMap api.TcpStreamMap, outputItems chan *api.OutputChannelItem, extensions []*api.Extension, updateTargetsQueue *queue.Queue) {
	sortedPackets := make(chan *wcap.SortedPacket, misc.PacketChannelBufferSize)
	writer, err := wcap.NewWriter(misc.DefaultContext)
	if err != nil {
		log.Error().Err(err).Msg("Failed creating writer:")
		return
	}
	go writer.Write(sortedPackets)

	assembler := initializeWorker(
		opts,
		outputItems,
		streamsMap,
		sortedPackets,
	)
	go startAssembler(streamsMap, assembler)

	if *tls {
		for _, e := range extensions {
			if e.Protocol.Name == "http" {
				target.TracerInstance = startTracer(
					e,
					outputItems,
					streamsMap,
					updateTargetsQueue,
					assembler,
				)
				break
			}
		}
	}
}

func printPeriodicStats(cleaner *Cleaner, assembler *assemblers.TcpAssembler) {
	statsPeriod := time.Second * time.Duration(*statsevery)
	ticker := time.NewTicker(statsPeriod)

	logicalCoreCount, err := cpu.Counts(true)
	if err != nil {
		logicalCoreCount = -1
	}

	physicalCoreCount, err := cpu.Counts(false)
	if err != nil {
		physicalCoreCount = -1
	}

	for {
		<-ticker.C

		errorMapLen, errorsSummary := diagnose.ErrorsMap.GetErrorsSummary()

		memStats := runtime.MemStats{}
		runtime.ReadMemStats(&memStats)
		sysInfo, err := pidusage.GetStat(os.Getpid())
		if err != nil {
			sysInfo = &pidusage.SysInfo{
				CPU:    -1,
				Memory: -1,
			}
		}

		cleanStats := cleaner.dumpStats()
		assemblerStats := assembler.DumpStats()
		currentAppStats := diagnose.AppStats.DumpStats()

		packetsReceived, packetsDropped, err := target.PacketSourceManager.Stats()
		if err != nil {
			packetsReceived = -1
			packetsDropped = -1
		}

		table1 = append(table1, table.Row{
			time.Now(),
			time.Since(diagnose.AppStats.StartTime),
			diagnose.ErrorsMap.ErrorsCount,
			errorMapLen,
			errorsSummary,
		})

		table2 = append(table2, table.Row{
			units.HumanSize(float64(memStats.Alloc)),
			units.HumanSize(float64(memStats.TotalAlloc)),
			units.HumanSize(float64(memStats.Sys)),
			units.HumanSize(float64(memStats.HeapAlloc)),
			units.HumanSize(float64(memStats.HeapIdle)),
			memStats.HeapObjects,
			units.HumanSize(sysInfo.Memory),
			memStats.NumGC,
			runtime.NumGoroutine(),
			sysInfo.CPU,
			logicalCoreCount,
			physicalCoreCount,
			countOpenFiles(),
		})

		table3 = append(table3, table.Row{
			assemblerStats.FlushedConnections,
			assemblerStats.ClosedConnections,
			cleanStats.deleted,
			currentAppStats.ProcessedBytes,
			currentAppStats.PacketsCount,
			currentAppStats.TcpPacketsCount,
			currentAppStats.DnsPacketsCount,
			currentAppStats.ReassembledTcpPayloadsCount,
			currentAppStats.MatchedPairs,
			currentAppStats.DroppedTcpStreams,
			currentAppStats.LiveTcpStreams,
			packetsReceived,
			packetsDropped,
			assembler.Dump(),
		})

		table1Header := table.Row{
			"Timestamp",
			"Time Passed",
			"Errors",
			"Error Types",
			"Errors Summary",
		}

		table2Header := table.Row{
			"Alloc",
			"Total Alloc",
			"System Memory",
			"Heap Alloc",
			"Heap Idle",
			"Heap Objects",
			"Memory RSS",
			"GC Cycles",
			"Goroutines",
			"CPU",
			"Logical Cores",
			"Physical Cores",
			"Open Files",
		}

		table3Header := table.Row{
			"Flushed Conn",
			"Closed Conn",
			"Deleted Conn",
			"Processed Bytes",
			"Total Packets",
			"TCP Packets",
			"UDP Packets",
			"Reassembled",
			"Matched Pairs",
			"Dropped TCP Streams",
			"Live TCP Streams",
			"Packets Received",
			"Packets Dropped",
		}

		fmt.Printf("\n------------------ PERIODIC STATS ------------------\n\n")

		t1 := table.NewWriter()
		t1.SetOutputMirror(os.Stdout)
		t1.AppendHeader(table1Header)
		t1.AppendRows(table1)
		t1.AppendFooter(table.Row{""})
		t1.SetStyle(table.StyleColoredBright)
		t1.Render()
		fmt.Println()

		t2 := table.NewWriter()
		t2.SetOutputMirror(os.Stdout)
		t2.AppendHeader(table2Header)
		t2.AppendRows(table2)
		t2.AppendFooter(table.Row{""})
		t2.SetStyle(table.StyleColoredBright)
		t2.Render()
		fmt.Println()

		t3 := table.NewWriter()
		t3.SetOutputMirror(os.Stdout)
		t3.AppendHeader(table3Header)
		t3.AppendRows(table3)
		t3.AppendFooter(table.Row{""})
		t3.SetStyle(table.StyleColoredBright)
		t3.Render()
		fmt.Println()
	}
}

func countOpenFiles() int64 {
	out, err := exec.Command("/bin/sh", "-c", fmt.Sprintf("lsof -p %v", os.Getpid())).Output()
	if err != nil {
		fmt.Println(err.Error())
	}
	lines := strings.Split(string(out), "\n")
	return int64(len(lines) - 1)
}

func initializePacketSources() error {
	if target.PacketSourceManager != nil {
		target.PacketSourceManager.Close()
	}

	var err error
	target.PacketSourceManager, err = source.NewPacketSourceManager(*procfs, *iface, *servicemesh, misc.TargetedPods, *packetCapture, target.MainPacketInputChan)
	return err
}

func initializeWorker(
	opts *misc.Opts,
	outputItems chan *api.OutputChannelItem,
	streamsMap api.TcpStreamMap,
	sortedPackets chan<- *wcap.SortedPacket,
) *assemblers.TcpAssembler {
	diagnose.InitializeErrorsMap(*debug, *verbose, *quiet)

	target.MainPacketInputChan = make(chan source.TcpPacketInfo, misc.PacketChannelBufferSize)

	if err := initializePacketSources(); err != nil {
		log.Fatal().Err(err).Send()
	}

	opts.StaleConnectionTimeout = time.Duration(*staleTimeoutSeconds) * time.Second

	return assemblers.NewTcpAssembler(
		"",
		assemblers.MasterCapture,
		sortedPackets,
		outputItems,
		streamsMap,
		opts,
	)
}

func startAssembler(streamsMap api.TcpStreamMap, assembler *assemblers.TcpAssembler) {
	go streamsMap.CloseTimedoutTcpStreamChannels()

	diagnose.AppStats.SetStartTime(time.Now())

	staleConnectionTimeout := time.Second * time.Duration(*staleTimeoutSeconds)
	cleaner := Cleaner{
		assembler:         assembler.Assembler,
		cleanPeriod:       cleanPeriod,
		connectionTimeout: staleConnectionTimeout,
		streamsMap:        streamsMap,
	}
	cleaner.start()

	if *debug {
		go printPeriodicStats(&cleaner, assembler)
	}

	assembler.ProcessPackets(target.MainPacketInputChan)

	if diagnose.ErrorsMap.OutputLevel >= 2 {
		assembler.DumpStreamPool()
	}

	if err := diagnose.DumpMemoryProfile(*memprofile); err != nil {
		log.Error().Err(err).Msg("Couldn't dump memory profile!")
	}

	assembler.WaitAndDump()

	diagnose.ErrorsMap.PrintSummary()
	log.Info().Interface("AppStats", diagnose.AppStats).Send()
}

func startTracer(
	extension *api.Extension,
	outputItems chan *api.OutputChannelItem,
	streamsMap api.TcpStreamMap,
	updateTargetsQueue *queue.Queue,
	assembler *assemblers.TcpAssembler,
) *tracer.Tracer {
	tls := tracer.Tracer{}
	chunksBufferSize := os.Getpagesize() * 100
	logBufferSize := os.Getpagesize()

	if err := tls.Init(
		chunksBufferSize,
		logBufferSize,
		*procfs,
		extension,
		assembler,
	); err != nil {
		tracer.LogError(err)
		return nil
	}

	if err := tracer.UpdateTargets(&tls, &misc.TargetedPods, *procfs); err != nil {
		tracer.LogError(err)
		return nil
	}

	updateTargetsQueue.AddJob(
		queue.Job{
			Name: "Start tracer UpdateTargets",
			Action: func() error {
				err := tracer.UpdateTargets(&tls, &misc.TargetedPods, *procfs)
				return err
			},
		},
	)

	// A quick way to instrument libssl.so without PID filtering - used for debuging and troubleshooting
	//
	if os.Getenv("KUBESHARK_GLOBAL_LIBSSL_PID") != "" {
		if err := tls.GlobalSSLLibTarget(*procfs, os.Getenv("KUBESHARK_GLOBAL_LIBSSL_PID")); err != nil {
			tracer.LogError(err)
			return nil
		}
	}

	// A quick way to instrument Go `crypto/tls` without PID filtering - used for debuging and troubleshooting
	//
	if os.Getenv("KUBESHARK_GLOBAL_GOLANG_PID") != "" {
		if err := tls.GlobalGoTarget(*procfs, os.Getenv("KUBESHARK_GLOBAL_GOLANG_PID")); err != nil {
			tracer.LogError(err)
			return nil
		}
	}

	go tls.PollForLogging()
	go tls.Poll(outputItems, streamsMap)

	return &tls
}
