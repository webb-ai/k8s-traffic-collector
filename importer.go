package main

import (
	"os"
	"path/filepath"
	"time"

	"github.com/kubeshark/base/pkg/api"
	"github.com/kubeshark/worker/assemblers"
	"github.com/kubeshark/worker/diagnose"
	"github.com/kubeshark/worker/kubernetes/resolver"
	"github.com/kubeshark/worker/misc"
	"github.com/kubeshark/worker/source"
	"github.com/rs/zerolog/log"
)

func startImporter(folder string, opts *misc.Opts, streamsMap api.TcpStreamMap, outputItems chan *api.OutputChannelItem) {
	diagnose.InitializeErrorsMap(*debug, *verbose, *quiet)
	diagnose.InitializeWorkerInternalStats()

	packets := make(chan source.TcpPacketInfo)
	opts.StaleConnectionTimeout = time.Duration(*staleTimeoutSeconds) * time.Second

	assembler := assemblers.NewTcpAssembler("", true, outputItems, streamsMap, opts)

	go func() {
		for {
			packetInfo, ok := <-packets
			if !ok {
				break
			}
			assembler.ProcessPacket(packetInfo, false)
		}
	}()

	err := walkFolder(folder, packets, opts)
	if err != nil {
		log.Error().Err(err).Send()
	}
}

func walkFolder(folder string, packets chan<- source.TcpPacketInfo, opts *misc.Opts) error {
	walker := func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()

		ext := filepath.Ext(file.Name())
		if ext != ".pcap" {
			return nil
		}

		log.Info().Str("pcap", file.Name()).Msg("Found PCAP file:")

		nameResolutionHistoryPath := filepath.Join(filepath.Dir(file.Name()), misc.NameResolutionHistoryFilename)
		resolver.K8sResolver.RestoreNameResolutionHistory(nameResolutionHistoryPath)

		hostSource, err := source.NewHostPacketSource(file.Name(), *iface, *packetCapture)
		if err != nil {
			return err
		}

		hostSource.ReadPackets(packets, true, true)

		return nil
	}

	err := filepath.Walk(folder, walker)
	return err
}
