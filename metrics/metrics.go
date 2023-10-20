package metrics

import (
	"fmt"
	"github.com/kubeshark/worker/pkg/api"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog/log"
	corev1 "k8s.io/api/core/v1"
	"net/http"
	"strconv"
	"strings"
)

const (
	DestinationEndpoint  = "destination_endpoint"
	DestinationHost      = "destination_host"
	DestinationIP        = "destination_ip"
	DestinationPod       = "destination_pod"
	DestinationPort      = "destination_port"
	DestinationService   = "destination_service"
	DestinationNameSpace = "destination_namespace"
	Endpoint             = "endpoint"
	Method               = "method"
	Protocol             = "protocol"
	SourceEndpoint       = "source_endpoint"
	SourceIP             = "source_ip"
	SourceNameSpace      = "source_namespace"
	SourcePod            = "source_pod"
	SourceService        = "source_service"
	StatusCode           = "status_code"
)

var allMetrics = newMetrics()

type metrics struct {
	RequestCountTotal      *prometheus.CounterVec
	RequestDurationSeconds *prometheus.HistogramVec
	RequestSizeBytes       *prometheus.HistogramVec
	ResponseSizeBytes      *prometheus.HistogramVec
}

func newMetrics() *metrics {
	labels := []string{DestinationEndpoint, DestinationHost, DestinationIP, DestinationPod, DestinationPort,
		DestinationService, DestinationNameSpace, Endpoint, Method, Protocol, SourceEndpoint, SourceIP,
		SourceNameSpace, SourcePod, SourceService, StatusCode}
	requestCount := promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "request_count_total",
			Help: "Counts the total number of requests.",
		},
		labels,
	)
	requestDuration := promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "request_duration_seconds",
			Help: "Tracks the request latency.",
		},
		labels,
	)
	requestSize := promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "request_size_bytes",
			Help: "Tracks the request size.",
		},
		labels,
	)
	responseSize := promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "response_size_bytes",
			Help: "Tracks the response size.",
		},
		labels,
	)
	return &metrics{
		RequestCountTotal:      requestCount,
		RequestDurationSeconds: requestDuration,
		RequestSizeBytes:       requestSize,
		ResponseSizeBytes:      responseSize,
	}
}

func getEndpointName(endpoint *corev1.Endpoints) string {
	if endpoint == nil {
		return ""
	}
	return endpoint.Name
}

func getServiceName(service *corev1.Service) string {
	if service == nil {
		return ""
	}
	return service.Name
}

func getPodOwner(pod *corev1.Pod) string {
	if pod == nil {
		return ""
	}
	for _, ref := range pod.GetOwnerReferences() {
		if ref.Kind == "Deployment" || ref.Kind == "StatefulSet" || ref.Kind == "DaemonSet" || ref.Kind == "CronJob" || ref.Kind == "Job" {
			return fmt.Sprintf("%s|%s|%s", ref.APIVersion, ref.Kind, ref.Name)
		}

		if ref.Kind == "ReplicaSet" {
			lastDashIndex := strings.LastIndex(ref.Name, "-")
			if lastDashIndex == -1 {
				// shouldn't happen
				return ""
			}
			deployName := ref.Name[:lastDashIndex]

			return fmt.Sprintf("apps/v1|Deployment|%s", deployName)
		}
	}

	return ""
}

func Record(entry *api.Entry) {
	durationSeconds := float64(entry.ElapsedTime) / 1000.0
	labels := map[string]string{
		DestinationEndpoint:  getEndpointName(entry.Destination.EndpointSlice),
		DestinationIP:        entry.Destination.IP,
		DestinationNameSpace: entry.Destination.Namespace,
		DestinationPod:       getPodOwner(entry.Destination.Pod),
		DestinationPort:      entry.Destination.Port,
		DestinationService:   getServiceName(entry.Destination.Service),
		SourceEndpoint:       getEndpointName(entry.Source.EndpointSlice),
		SourceIP:             entry.Source.IP,
		SourceNameSpace:      entry.Source.Namespace,
		SourcePod:            getPodOwner(entry.Source.Pod),
		SourceService:        getServiceName(entry.Source.Service),
		Protocol:             entry.Protocol.Name,
		DestinationHost:      "",
		Endpoint:             "",
		Method:               "",
		StatusCode:           "",
	}

	if labels[SourcePod] == "" {
		return
	}

	switch entry.Protocol.Name {
	case "http":
		request := entry.Request
		response := entry.Response
		if request["method"] != nil {
			labels[Method] = request["method"].(string)
		}
		if request["path"] != nil {
			labels[Endpoint] = request["path"].(string)
		}
		if response["status"] != nil {
			labels[StatusCode] = strconv.Itoa(int(response["status"].(float64)))
		}
		if request["headers"].(map[string]interface{})["Host"] != nil {
			labels[DestinationHost] = request["headers"].(map[string]interface{})["Host"].(string)
		}

	case "dns":
	}

	allMetrics.RequestCountTotal.With(labels).Inc()
	allMetrics.RequestDurationSeconds.With(labels).Observe(durationSeconds)
	allMetrics.RequestSizeBytes.With(labels).Observe(float64(entry.RequestSize))
	allMetrics.ResponseSizeBytes.With(labels).Observe(float64(entry.ResponseSize))
}

func StartMetricsServer(port, endpoint string) {
	log.Info().Msgf("starting metrics server at endpoint %s of port %s", endpoint, port)
	http.Handle(endpoint, Handler())
	go http.ListenAndServe(port, nil)
}

func Handler() http.Handler {
	reg := prometheus.NewRegistry()
	reg.MustRegister(
		allMetrics.RequestCountTotal,
		allMetrics.RequestSizeBytes,
		allMetrics.ResponseSizeBytes,
		allMetrics.RequestDurationSeconds,
	)
	return promhttp.HandlerFor(reg, promhttp.HandlerOpts{})
}
