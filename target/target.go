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
	success := true

	misc.TargettedPods = pods

	PacketSourceManager.UpdatePods(pods, MainPacketInputChan)

	if TracerInstance != nil && os.Getenv("KUBESHARK_GLOBAL_GOLANG_PID") == "" {
		if err := tracer.UpdateTargets(TracerInstance, &pods, procfs); err != nil {
			tracer.LogError(err)
			success = false
		}
	}

	printNewTargets(success)
}

func printNewTargets(success bool) {
	printStr := ""
	for _, pod := range misc.TargettedPods {
		printStr += fmt.Sprintf("%s (%s), ", pod.Status.PodIP, pod.Name)
	}
	printStr = strings.TrimRight(printStr, ", ")

	if success {
		log.Info().Msg(fmt.Sprintf("Now targetting: %s", printStr))
	} else {
		log.Error().Msg(fmt.Sprintf("Failed to start targetting: %s", printStr))
	}
}
