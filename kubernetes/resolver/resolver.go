package resolver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/kubeshark/worker/misc"
	"github.com/kubeshark/worker/pkg/api"
	"github.com/rs/zerolog/log"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	restclient "k8s.io/client-go/rest"
)

const (
	kubClientNullString = "None"
)

type Resolver struct {
	clientConfig   *restclient.Config
	clientSet      *kubernetes.Clientset
	nameMap        *sync.Map
	nameMapHistory *sync.Map
	isStarted      bool
	errOut         chan error
}

func (resolver *Resolver) Start(ctx context.Context, nameResolutionHistoryPath string, clusterMode bool) {
	if !resolver.isStarted {
		resolver.isStarted = true

		resolver.RestoreNameResolutionHistory(nameResolutionHistoryPath)

		if clusterMode {
			go resolver.dumpNameResolutionHistoryEveryNSeconds(3)
			go resolver.infiniteErrorHandleRetryFunc(ctx, resolver.watchServices)
			go resolver.infiniteErrorHandleRetryFunc(ctx, resolver.watchEndpoints)
			go resolver.infiniteErrorHandleRetryFunc(ctx, resolver.watchPods)
		}
	}
}

func (resolver *Resolver) Resolve(name string, timestamp int64) *api.Resolution {
	resolvedName, isFound := resolver.getMap(timestamp)[name]
	if !isFound {
		return nil
	}
	return resolvedName
}

func (resolver *Resolver) getMap(timestamp int64) map[string]*api.Resolution {
	nameMap := make(map[string]*api.Resolution)
	resolver.nameMapHistory.Range(func(k, v interface{}) bool {
		t := k.(int64)
		if t > timestamp {
			return true
		}
		nameMap = v.(map[string]*api.Resolution)
		return true
	})
	return nameMap
}

func (resolver *Resolver) updateNameResolutionHistory() {
	nameMap := make(map[string]*api.Resolution)
	resolver.nameMap.Range(func(k, v interface{}) bool {
		key := k.(string)
		nameMap[key] = v.(*api.Resolution)
		return true
	})
	resolver.nameMapHistory.Store(time.Now().Unix(), nameMap)
	log.Debug().Msg("Updated the name resolution history.")
}

func (resolver *Resolver) dumpNameResolutionHistoryEveryNSeconds(n time.Duration) {
	resolver.dumpNameResolutionHistoryWrapper()
	for range time.Tick(time.Second * n) {
		resolver.dumpNameResolutionHistoryWrapper()
	}
}

func (resolver *Resolver) GetDumpNameResolutionHistoryMap() map[int64]map[string]*api.Resolution {
	m := make(map[int64]map[string]*api.Resolution)
	resolver.nameMapHistory.Range(func(key, value interface{}) bool {
		m[key.(int64)] = value.(map[string]*api.Resolution)
		return true
	})

	return m
}

func (resolver *Resolver) GetDumpNameResolutionHistoryMapStringKeys() map[string]map[string]*api.Resolution {
	m := make(map[string]map[string]*api.Resolution)
	resolver.nameMapHistory.Range(func(key, value interface{}) bool {
		m[strconv.FormatInt(key.(int64), 10)] = value.(map[string]*api.Resolution)
		return true
	})

	return m
}

func (resolver *Resolver) dumpNameResolutionHistoryWrapper() {
	err := resolver.dumpNameResolutionHistory()
	if err != nil {
		log.Error().Err(err).Msg("Failed dumping the name resolution history:")
	}
}

func (resolver *Resolver) dumpNameResolutionHistory() error {
	m := resolver.GetDumpNameResolutionHistoryMap()

	b, err := json.Marshal(m)
	if err != nil {
		return err
	}

	err = os.WriteFile(misc.GetNameResolutionHistoryPath(), b, 0644)
	if err != nil {
		return err
	}

	return nil
}

func (resolver *Resolver) RestoreNameResolutionHistory(nameResolutionHistoryPath string) {
	content, err := os.ReadFile(nameResolutionHistoryPath)
	if err != nil {
		log.Warn().Str("path", nameResolutionHistoryPath).Err(err).Msg("Failed reading the name resolution history dump:")
		return
	}

	m := make(map[int64]map[string]*api.Resolution)
	err = json.Unmarshal(content, &m)
	if err != nil {
		log.Warn().Str("path", nameResolutionHistoryPath).Err(err).Msg("Failed unmarshalling the name resolution history dump:")
		return
	}

	for k, v := range m {
		resolver.nameMapHistory.Store(k, v)
	}

	log.Info().Str("path", nameResolutionHistoryPath).Int("count", len(m)).Msg("Restored the name resolution history")
}

func (resolver *Resolver) watchPods(ctx context.Context) error {
	// empty namespace makes the client watch all namespaces
	watcher, err := resolver.clientSet.CoreV1().Pods(getSelfNamespace()).Watch(ctx, metav1.ListOptions{Watch: true})
	if err != nil {
		return err
	}
	for {
		select {
		case event := <-watcher.ResultChan():
			if event.Object == nil {
				return errors.New("error in kubectl pod watch")
			}

			pod := event.Object.(*corev1.Pod)
			resolver.SaveResolution(pod.Status.PodIP, &api.Resolution{
				Name:      pod.Name,
				Namespace: pod.Namespace,
				Pod:       pod,
			}, event.Type)
		case <-ctx.Done():
			watcher.Stop()
			return nil
		}
	}
}

func (resolver *Resolver) watchEndpoints(ctx context.Context) error {
	// empty namespace makes the client watch all namespaces
	watcher, err := resolver.clientSet.CoreV1().Endpoints(getSelfNamespace()).Watch(ctx, metav1.ListOptions{Watch: true})
	if err != nil {
		return err
	}
	for {
		select {
		case event := <-watcher.ResultChan():
			if event.Object == nil {
				return errors.New("error in kubectl endpoint watch")
			}
			endpoint := event.Object.(*corev1.Endpoints)
			if endpoint.Subsets != nil {
				for _, subset := range endpoint.Subsets {
					var ports []int32
					if subset.Ports != nil {
						for _, portMapping := range subset.Ports {
							if portMapping.Port > 0 {
								ports = append(ports, portMapping.Port)
							}
						}
					}
					if subset.Addresses != nil {
						for _, address := range subset.Addresses {
							resolver.SaveResolution(address.IP, &api.Resolution{
								Name:          endpoint.Name,
								Namespace:     endpoint.Namespace,
								EndpointSlice: endpoint,
							}, event.Type)
							for _, port := range ports {
								ipWithPort := fmt.Sprintf("%s:%d", address.IP, port)
								resolver.SaveResolution(ipWithPort, &api.Resolution{
									Name:          endpoint.Name,
									Namespace:     endpoint.Namespace,
									EndpointSlice: endpoint,
								}, event.Type)
							}
						}
					}

				}
			}
		case <-ctx.Done():
			watcher.Stop()
			return nil
		}
	}
}

func (resolver *Resolver) watchServices(ctx context.Context) error {
	// empty namespace makes the client watch all namespaces
	watcher, err := resolver.clientSet.CoreV1().Services(getSelfNamespace()).Watch(ctx, metav1.ListOptions{Watch: true})
	if err != nil {
		return err
	}
	for {
		select {
		case event := <-watcher.ResultChan():
			if event.Object == nil {
				return errors.New("error in kubectl service watch")
			}

			service := event.Object.(*corev1.Service)
			if service.Spec.ClusterIP != "" && service.Spec.ClusterIP != kubClientNullString {
				resolver.SaveResolution(service.Spec.ClusterIP, &api.Resolution{
					Name:      service.Name,
					Namespace: service.Namespace,
					Service:   service,
				}, event.Type)
				if service.Spec.Ports != nil {
					for _, port := range service.Spec.Ports {
						if port.Port > 0 {
							resolver.SaveResolution(fmt.Sprintf("%s:%d", service.Spec.ClusterIP, port.Port), &api.Resolution{
								Name:      service.Name,
								Namespace: service.Namespace,
								Service:   service,
							}, event.Type)
						}
					}
				}
			}
			if service.Status.LoadBalancer.Ingress != nil {
				for _, ingress := range service.Status.LoadBalancer.Ingress {
					resolver.SaveResolution(ingress.IP, &api.Resolution{
						Name:      service.Name,
						Namespace: service.Namespace,
						Service:   service,
					}, event.Type)
					for _, port := range ingress.Ports {
						resolver.SaveResolution(fmt.Sprintf("%s:%d", ingress.IP, port.Port), &api.Resolution{
							Name:      service.Name,
							Namespace: service.Namespace,
							Service:   service,
						}, event.Type)
					}
				}
			}
		case <-ctx.Done():
			watcher.Stop()
			return nil
		}
	}
}

func (resolver *Resolver) SaveResolution(key string, resolution *api.Resolution, eventType watch.EventType) {
	if eventType == watch.Deleted {
		resolver.nameMap.Delete(key)
		log.Debug().Str("key", key).Interface("resolution", resolution).Str("operation", "delete").Send()
	} else {
		_oldResolution, ok := resolver.nameMap.Load(key)
		if ok {
			oldResolution := _oldResolution.(*api.Resolution)

			if resolution.Name != "" && (resolution.Service != nil || (oldResolution.Service == nil && resolution.EndpointSlice != nil) || (oldResolution.Service == nil && oldResolution.EndpointSlice == nil && resolution.Pod != nil)) {
				oldResolution.Name = resolution.Name
			}

			if resolution.Namespace != "" {
				oldResolution.Namespace = resolution.Namespace
			}

			if resolution.Pod != nil {
				oldResolution.Pod = resolution.Pod
			}
			if resolution.EndpointSlice != nil {
				oldResolution.EndpointSlice = resolution.EndpointSlice
			}
			if resolution.Service != nil {
				oldResolution.Service = resolution.Service
			}

			resolution = oldResolution
		}

		resolver.nameMap.Store(key, resolution)
		log.Debug().Str("key", key).Interface("resolution", resolution).Str("operation", "store").Send()
	}

	resolver.updateNameResolutionHistory()
}

func (resolver *Resolver) infiniteErrorHandleRetryFunc(ctx context.Context, fun func(ctx context.Context) error) {
	for {
		err := fun(ctx)
		if err != nil {
			resolver.errOut <- err

			var statusError *k8serrors.StatusError
			if errors.As(err, &statusError) {
				if statusError.ErrStatus.Reason == metav1.StatusReasonForbidden {
					log.Warn().Err(err).Msg("Resolver loop encountered permission error, aborting event listening...")
					return
				}
			}
		}
		if ctx.Err() != nil { // context was cancelled or errored
			return
		}
	}
}
