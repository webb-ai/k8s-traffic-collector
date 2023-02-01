package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/kubeshark/base/pkg/api"
	"github.com/kubeshark/base/pkg/extensions"
	"github.com/kubeshark/worker/assemblers"
	"github.com/kubeshark/worker/diagnose"
	"github.com/kubeshark/worker/kubernetes/resolver"
	"github.com/kubeshark/worker/misc"
	"github.com/kubeshark/worker/server"
	"github.com/kubeshark/worker/utils"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"k8s.io/client-go/rest"
)

var port = flag.Int("port", 80, "Port number of the HTTP server")

// capture
var iface = flag.String("i", "en0", "Interface to read packets from")
var folder = flag.String("f", "", "Folder that contains a PCAP snapshot")
var staleTimeoutSeconds = flag.Int("staletimout", 120, "Max time in seconds to keep connections which don't transmit data")
var servicemesh = flag.Bool("servicemesh", false, "Record decrypted traffic if the cluster is configured with a service mesh and with mtls")
var tls = flag.Bool("tls", false, "Enable TLS tracing")
var packetCapture = flag.String("packet-capture", "libpcap", "Packet capture backend. Possible values: libpcap, af_packet")
var procfs = flag.String("procfs", "/proc", "The procfs directory, used when mapping host volumes into a container")

// development
var debug = flag.Bool("debug", false, "Enable debug mode")
var quiet = flag.Bool("quiet", false, "Be quiet regarding errors")
var verbose = flag.Bool("verbose", false, "Be verbose")
var statsevery = flag.Int("stats", 60, "Output statistics every N seconds")
var memprofile = flag.String("memprofile", "", "Write memory profile")

func main() {
	flag.Parse()

	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}).With().Caller().Logger()

	if *debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}

	misc.InitDataDir()
	misc.InitAlivePcapsMap()

	run()
}

func run() {
	log.Info().Msg("Starting worker...")

	_, err := rest.InClusterConfig()
	opts := &misc.Opts{
		ClusterMode: err == nil,
	}
	streamsMap := assemblers.NewTcpStreamMap(true)

	outputItems := make(chan *api.OutputChannelItem)

	resolver.StartResolving("", misc.GetNameResolutionHistoryPath(), opts.ClusterMode)

	if assemblers.GetMemoryProfilingEnabled() {
		diagnose.StartMemoryProfiler(
			os.Getenv(assemblers.MemoryProfilingDumpPath),
			os.Getenv(assemblers.MemoryProfilingTimeIntervalSeconds),
			os.Getenv(assemblers.MemoryUsageTimeIntervalMilliseconds))
	}

	if *folder != "" {
		startImporter(*folder, opts, streamsMap, outputItems)
	} else {
		startWorker(opts, streamsMap, outputItems, extensions.Extensions)
		go handleCapturedItems(outputItems)
	}

	ginApp := server.Build(opts, *procfs)
	server.Start(ginApp, *port)
}

func handleCapturedItems(outputItems chan *api.OutputChannelItem) {
	for item := range outputItems {
		// TODO: The previously bad design forces us to Marshal and Unmarshal
		data, err := json.Marshal(item)
		if err != nil {
			log.Error().Err(err).Msg("Failed marshalling item:")
			continue
		}
		var finalItem *api.OutputChannelItem
		err = json.Unmarshal(data, &finalItem)
		if err != nil {
			log.Error().Err(err).Msg("Failed unmarshalling item:")
			continue
		}

		entry := utils.ItemToEntry(finalItem)
		// TODO: vm.Call("capturedItem", nil, Entry)
		fmt.Printf("entry: %+v\n", entry)
	}
}
