package misc

import (
	"net"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	v1 "k8s.io/api/core/v1"
)

type Opts struct {
	ClusterMode            bool
	StaleConnectionTimeout time.Duration
}

var TargettedPods []v1.Pod // global

var Snaplen int = 65536

var AlivePcaps *sync.Map

func InitAlivePcapsMap() {
	AlivePcaps = &sync.Map{}
}

func RemovePortFromWorkerHost(workerHost string) string {
	host, _, err := net.SplitHostPort(workerHost)
	if err != nil {
		log.Error().Err(err).Send()
		return workerHost
	}

	return host
}
