package target

import (
	"fmt"
	"os"
	"strings"

	"github.com/kubeshark/worker/misc"
	"github.com/kubeshark/worker/source"
	"github.com/kubeshark/worker/tracer"
	"github.com/rs/zerolog/log"
	v1 "k8s.io/api/core/v1"
)

var PacketSourceManager *source.PacketSourceManager // global
var MainPacketInputChan chan source.TcpPacketInfo   // global
var TracerInstance *tracer.Tracer                   // global

func UpdatePods(pods []v1.Pod, procfs string) {
	misc.TargetedPods = pods

	if PacketSourceManager != nil {
		PacketSourceManager.UpdatePods(pods, MainPacketInputChan)
	}

	if TracerInstance != nil && os.Getenv("KUBESHARK_GLOBAL_GOLANG_PID") == "" {
		go tracer.UpdateTargets(TracerInstance, &pods, procfs)
	}

	printNewTargets()
}

func printNewTargets() {
	printStr := ""
	for _, pod := range misc.TargetedPods {
		printStr += fmt.Sprintf("%s (%s), ", pod.Status.PodIP, pod.Name)
	}
	printStr = strings.TrimRight(printStr, ", ")

	log.Info().Msg(fmt.Sprintf("Now targeting: %s", printStr))
}
