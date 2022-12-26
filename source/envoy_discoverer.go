package source

import (
	"fmt"
	"os"
	"strings"

	"github.com/rs/zerolog/log"
	v1 "k8s.io/api/core/v1"
)

const envoyBinary = "/envoy"

func discoverRelevantEnvoyPids(procfs string, pods []v1.Pod) ([]string, error) {
	result := make([]string, 0)

	pids, err := os.ReadDir(procfs)

	if err != nil {
		return result, err
	}

	log.Info().Str("procfs", procfs).Int("pids", len(pids)).Msg("Starting Envoy auto discoverer:")

	for _, pid := range pids {
		if !pid.IsDir() {
			continue
		}

		if !numberRegex.MatchString(pid.Name()) {
			continue
		}

		if checkEnvoyPid(procfs, pid.Name(), pods) {
			result = append(result, pid.Name())
		}
	}

	log.Info().Msg(fmt.Sprintf("Found %v relevant Envoy processes - %v", len(result), result))

	return result, nil
}

func checkEnvoyPid(procfs string, pid string, pods []v1.Pod) bool {
	execLink := fmt.Sprintf("%v/%v/exe", procfs, pid)
	exec, err := os.Readlink(execLink)

	if err != nil {
		// Debug on purpose - it may happen due to many reasons and we only care
		//	for it during troubleshooting
		//
		log.Debug().Msg(fmt.Sprintf("Unable to read link %v - %v\n", execLink, err))
		return false
	}

	if !strings.HasSuffix(exec, envoyBinary) {
		return false
	}

	environmentFile := fmt.Sprintf("%v/%v/environ", procfs, pid)
	podIp, err := getSingleValueFromEnvironmentVariableFile(environmentFile, "INSTANCE_IP")

	if err != nil {
		return false
	}

	if podIp == "" {
		log.Debug().Msg(fmt.Sprintf("Found an Envoy process without INSTANCE_IP variable %v\n", pid))
		return false
	}

	log.Info().Msg(fmt.Sprintf("Found Envoy pid %v with cluster ip %v", pid, podIp))

	for _, pod := range pods {
		if pod.Status.PodIP == podIp {
			return true
		}
	}

	return false
}
