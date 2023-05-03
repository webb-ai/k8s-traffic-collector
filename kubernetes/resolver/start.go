package resolver

import (
	"context"

	"github.com/kubeshark/worker/misc"
	"github.com/rs/zerolog/log"
)

var K8sResolver *Resolver

func StartResolving(nameResolutionHistoryPath string, clusterMode bool) {
	errOut := make(chan error, misc.ErrorChannelBufferSize)
	res := NewFromInCluster(errOut)

	ctx := context.Background()
	res.Start(ctx, nameResolutionHistoryPath, clusterMode)
	go func() {
		for {
			err := <-errOut
			log.Error().Err(err).Msg("Name resolution failed:")
		}
	}()

	K8sResolver = res
}
