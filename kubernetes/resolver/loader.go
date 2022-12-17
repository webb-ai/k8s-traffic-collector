package resolver

import (
	"sync"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func NewFromInCluster(errOut chan error, namespace string) (*Resolver, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}
	clientSet, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	return &Resolver{clientConfig: config, clientSet: clientSet, nameMap: &sync.Map{}, serviceMap: &sync.Map{}, errOut: errOut, namespace: namespace}, nil
}
