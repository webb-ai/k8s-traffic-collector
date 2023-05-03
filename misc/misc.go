package misc

import (
	"net"
	"time"

	v1 "k8s.io/api/core/v1"
)

type Opts struct {
	ClusterMode            bool
	StaleConnectionTimeout time.Duration
}

var TargetedPods []v1.Pod // global

var Snaplen int = 65536

func RemovePortFromWorkerHost(workerHost string) string {
	host, _, err := net.SplitHostPort(workerHost)
	if err != nil {
		return workerHost
	}

	return host
}
