package health

import (
	"net/http"
	"sync/atomic"
)

// Readiness tracks whether the service is ready to receive traffic.
type Readiness struct {
	ready atomic.Bool
}

func NewReadiness(initial bool) *Readiness {
	r := &Readiness{}
	r.ready.Store(initial)
	return r
}

// SetReady updates the readiness state.
func (r *Readiness) SetReady(ready bool) {
	r.ready.Store(ready)
}

// Ready returns true if the service is ready.
func (r *Readiness) Ready() bool {
	return r.ready.Load()
}

// LivenessHandler always reports the process as live.
func LivenessHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
}

// ReadinessHandler reports readiness based on the tracker state.
func ReadinessHandler(r *Readiness) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if r.Ready() {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok\n"))
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("not ready\n"))
	})
}

// HealthHandler currently mirrors readiness.
func HealthHandler(r *Readiness) http.Handler {
	return ReadinessHandler(r)
}
