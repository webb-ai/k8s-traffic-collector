package metrics

import (
	"github.com/kubeshark/worker/pkg/api"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog/log"
	"net/http"
	"strconv"
)

const (
	SourceIP        = "source_ip"
	DestinationIP   = "destination_ip"
	DestinationHost = "destination_host"
	Protocol        = "protocol"
	Method          = "method"
	Endpoint        = "endpoint"
	StatusCode      = "status_code"
)

var allMetrics = newMetrics()

type metrics struct {
	RequestCountTotal      *prometheus.CounterVec
	RequestDurationSeconds *prometheus.HistogramVec
	RequestSizeBytes       *prometheus.HistogramVec
	ResponseSizeBytes      *prometheus.HistogramVec
}

func newMetrics() *metrics {
	labels := []string{SourceIP, DestinationIP, DestinationHost, Protocol, Method, Endpoint, StatusCode}
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

func Record(entry *api.Entry) {
	durationSeconds := float64(entry.ElapsedTime) / 1000.0
	labels := map[string]string{
		SourceIP:        entry.Source.IP,
		DestinationIP:   entry.Destination.IP,
		DestinationHost: "",
		Protocol:        entry.Protocol.Name,
		Method:          "",
		Endpoint:        "",
		StatusCode:      "",
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
