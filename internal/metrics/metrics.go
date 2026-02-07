package metrics

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	metricsNamespace = "gate"
)

// Registry holds metrics collectors for the Gate service.
type Registry struct {
	registry       *prometheus.Registry
	requests       *prometheus.CounterVec
	errors         *prometheus.CounterVec
	durations      *prometheus.HistogramVec
	activeSessions prometheus.Gauge
	terminated     *prometheus.CounterVec
	sshBytes       *prometheus.CounterVec
}

func New() *Registry {
	reg := prometheus.NewRegistry()

	requests := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "http_requests_total",
			Help:      "Total number of HTTP requests.",
		},
		[]string{"path", "method", "code"},
	)

	errors := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "http_request_errors_total",
			Help:      "Total number of HTTP error responses (4xx/5xx).",
		},
		[]string{"path", "method", "code"},
	)

	durations := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Name:      "http_request_duration_seconds",
			Help:      "HTTP request latency in seconds.",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"path", "method"},
	)

	activeSessions := prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Name:      "sessions_active",
			Help:      "Number of active SSH sessions.",
		},
	)

	terminated := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "sessions_terminated_total",
			Help:      "Total number of terminated SSH sessions.",
		},
		[]string{"reason"},
	)

	sshBytes := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "ssh_transport_bytes_total",
			Help:      "Total SSH transport bytes read and written by the server.",
		},
		[]string{"direction"},
	)

	reg.MustRegister(requests, errors, durations, activeSessions, terminated, sshBytes)

	return &Registry{
		registry:       reg,
		requests:       requests,
		errors:         errors,
		durations:      durations,
		activeSessions: activeSessions,
		terminated:     terminated,
		sshBytes:       sshBytes,
	}
}

// Handler returns an HTTP handler that exposes Prometheus metrics.
func (r *Registry) Handler() http.Handler {
	return promhttp.HandlerFor(r.registry, promhttp.HandlerOpts{})
}

// ObserveRequest records a completed HTTP request.
func (r *Registry) ObserveRequest(path, method string, status int, duration time.Duration) {
	code := strconv.Itoa(status)
	r.requests.WithLabelValues(path, method, code).Inc()
	r.durations.WithLabelValues(path, method).Observe(duration.Seconds())
	if status >= http.StatusBadRequest {
		r.errors.WithLabelValues(path, method, code).Inc()
	}
}

// SetActiveSessions sets the active session gauge.
func (r *Registry) SetActiveSessions(count int) {
	r.activeSessions.Set(float64(count))
}

// ObserveSessionTermination records a terminated session by reason.
func (r *Registry) ObserveSessionTermination(reason string) {
	r.terminated.WithLabelValues(reason).Inc()
}

// AddSSHTransportBytes records SSH transport bytes in the given direction ("rx" or "tx").
func (r *Registry) AddSSHTransportBytes(direction string, bytes int) {
	if bytes <= 0 {
		return
	}
	r.sshBytes.WithLabelValues(direction).Add(float64(bytes))
}
