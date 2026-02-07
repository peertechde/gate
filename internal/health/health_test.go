package health

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLivenessHandler(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/livez", nil)
	rec := httptest.NewRecorder()

	LivenessHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}
}

func TestReadinessHandler(t *testing.T) {
	readiness := NewReadiness(false)
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()

	ReadinessHandler(readiness).ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected status 503 when not ready, got %d", rec.Code)
	}

	readiness.SetReady(true)
	rec = httptest.NewRecorder()
	ReadinessHandler(readiness).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200 when ready, got %d", rec.Code)
	}
}
