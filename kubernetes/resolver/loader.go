package resolver

import (
	"sync"

	"github.com/rs/zerolog/log"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func NewFromInCluster(errOut chan error) *Resolver {
	config, err := rest.InClusterConfig()
	if err != nil {
		log.Warn().Err(err).Send()
	}

	var clientSet *kubernetes.Clientset
	if config != nil {
		clientSet, err = kubernetes.NewForConfig(config)
		if err != nil {
			log.Warn().Err(err).Send()
		}
	}

	return &Resolver{
		clientConfig:   config,
		clientSet:      clientSet,
		nameMap:        &sync.Map{},
		serviceMap:     &sync.Map{},
		nameMapHistory: &sync.Map{},
		errOut:         errOut,
	}
}
