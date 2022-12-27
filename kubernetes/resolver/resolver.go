package resolver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/kubeshark/worker/misc"
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
	serviceMap     *sync.Map
	nameMapHistory *sync.Map
	isStarted      bool
	errOut         chan error
	namespace      string
}

type ResolvedObjectInfo struct {
	FullAddress string
	Namespace   string
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

func (resolver *Resolver) Resolve(name string, timestamp int64) *ResolvedObjectInfo {
	resolvedName, isFound := resolver.getMap(timestamp)[name]
	if !isFound {
		return nil
	}
	return resolvedName
}

func (resolver *Resolver) getMap(timestamp int64) map[string]*ResolvedObjectInfo {
	nameMap := make(map[string]*ResolvedObjectInfo)
	resolver.nameMapHistory.Range(func(k, v interface{}) bool {
		t := k.(int64)
		if t > timestamp {
			return true
		}
		nameMap = v.(map[string]*ResolvedObjectInfo)
		return true
	})
	return nameMap
}

func (resolver *Resolver) updateNameResolutionHistory() {
	nameMap := make(map[string]*ResolvedObjectInfo)
	resolver.nameMap.Range(func(k, v interface{}) bool {
		key := k.(string)
		nameMap[key] = v.(*ResolvedObjectInfo)
		return true
	})
	resolver.nameMapHistory.Store(time.Now().Unix(), nameMap)
	log.Info().Msg("Updated the name resolution history.")
}

func (resolver *Resolver) dumpNameResolutionHistoryEveryNSeconds(n time.Duration) {
	resolver.dumpNameResolutionHistoryWrapper()
	for range time.Tick(time.Second * n) {
		resolver.dumpNameResolutionHistoryWrapper()
	}
}

func (resolver *Resolver) GetDumpNameResolutionHistoryMap() map[int64]interface{} {
	m := make(map[int64]interface{})
	resolver.nameMapHistory.Range(func(key, value interface{}) bool {
		m[key.(int64)] = value
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

	m := make(map[int64]interface{})
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

func (resolver *Resolver) CheckIsServiceIP(address string) bool {
	_, isFound := resolver.serviceMap.Load(address)
	return isFound
}

func (resolver *Resolver) watchPods(ctx context.Context) error {
	// empty namespace makes the client watch all namespaces
	watcher, err := resolver.clientSet.CoreV1().Pods(resolver.namespace).Watch(ctx, metav1.ListOptions{Watch: true})
	if err != nil {
		return err
	}
	for {
		select {
		case event := <-watcher.ResultChan():
			if event.Object == nil {
				return errors.New("error in kubectl pod watch")
			}
			if event.Type == watch.Deleted {
				pod := event.Object.(*corev1.Pod)
				resolver.saveResolvedName(pod.Status.PodIP, "", pod.Namespace, event.Type)
			}
		case <-ctx.Done():
			watcher.Stop()
			return nil
		}
	}
}

func (resolver *Resolver) watchEndpoints(ctx context.Context) error {
	// empty namespace makes the client watch all namespaces
	watcher, err := resolver.clientSet.CoreV1().Endpoints(resolver.namespace).Watch(ctx, metav1.ListOptions{Watch: true})
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
			serviceHostname := fmt.Sprintf("%s.%s", endpoint.Name, endpoint.Namespace)
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
							resolver.saveResolvedName(address.IP, serviceHostname, endpoint.Namespace, event.Type)
							for _, port := range ports {
								ipWithPort := fmt.Sprintf("%s:%d", address.IP, port)
								resolver.saveResolvedName(ipWithPort, serviceHostname, endpoint.Namespace, event.Type)
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
	watcher, err := resolver.clientSet.CoreV1().Services(resolver.namespace).Watch(ctx, metav1.ListOptions{Watch: true})
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
			serviceHostname := fmt.Sprintf("%s.%s", service.Name, service.Namespace)
			if service.Spec.ClusterIP != "" && service.Spec.ClusterIP != kubClientNullString {
				resolver.saveResolvedName(service.Spec.ClusterIP, serviceHostname, service.Namespace, event.Type)
				if service.Spec.Ports != nil {
					for _, port := range service.Spec.Ports {
						if port.Port > 0 {
							resolver.saveResolvedName(fmt.Sprintf("%s:%d", service.Spec.ClusterIP, port.Port), serviceHostname, service.Namespace, event.Type)
						}
					}
				}
				resolver.saveServiceIP(service.Spec.ClusterIP, serviceHostname, service.Namespace, event.Type)
			}
			if service.Status.LoadBalancer.Ingress != nil {
				for _, ingress := range service.Status.LoadBalancer.Ingress {
					resolver.saveResolvedName(ingress.IP, serviceHostname, service.Namespace, event.Type)
				}
			}
		case <-ctx.Done():
			watcher.Stop()
			return nil
		}
	}
}

func (resolver *Resolver) saveResolvedName(key string, resolved string, namespace string, eventType watch.EventType) {
	if eventType == watch.Deleted {
		resolver.nameMap.Delete(resolved)
		resolver.nameMap.Delete(key)
		log.Info().Msg(fmt.Sprintf("Nameresolver set %s=nil", key))
	} else {

		resolver.nameMap.Store(key, &ResolvedObjectInfo{FullAddress: resolved, Namespace: namespace})
		resolver.nameMap.Store(resolved, &ResolvedObjectInfo{FullAddress: resolved, Namespace: namespace})
		log.Info().Msg(fmt.Sprintf("Nameresolver set %s=%s", key, resolved))
	}

	resolver.updateNameResolutionHistory()
}

func (resolver *Resolver) saveServiceIP(key string, resolved string, namespace string, eventType watch.EventType) {
	if eventType == watch.Deleted {
		resolver.serviceMap.Delete(key)
	} else {
		resolver.nameMap.Store(key, &ResolvedObjectInfo{FullAddress: resolved, Namespace: namespace})
		log.Info().Msg(fmt.Sprintf("Nameresolver set %s=%s", key, resolved))

		resolver.updateNameResolutionHistory()
	}
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
