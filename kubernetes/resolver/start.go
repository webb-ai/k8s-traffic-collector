package resolver

import (
	"context"

	"github.com/rs/zerolog/log"
)

var K8sResolver *Resolver

func StartResolving(namespace string, nameResolutionHistoryPath string, clusterMode bool) {
	errOut := make(chan error, 100)
	res := NewFromInCluster(errOut, namespace)

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
