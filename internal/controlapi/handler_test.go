package controlapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"peertech.de/gate/internal/logging"
	"peertech.de/gate/internal/requestid"
	"peertech.de/gate/internal/session"
)

func TestListSessionsDefaultOrder(t *testing.T) {
	registry := session.NewRegistry(10, nil)

	first, err := registry.Create("alice", "SHA256:abc", "203.0.113.10", nil, nil)
	if err != nil {
		t.Fatalf("expected create to succeed: %v", err)
	}
	time.Sleep(2 * time.Millisecond)
	second, err := registry.Create("bob", "SHA256:def", "203.0.113.11", nil, nil)
	if err != nil {
		t.Fatalf("expected create to succeed: %v", err)
	}

	rec := performRequest(t, registry, http.MethodGet, "/api/v1/sessions")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var resp SessionListResponse
	decodeJSON(t, rec, &resp)
	if len(resp.Sessions) != 2 {
		t.Fatalf("expected 2 sessions, got %d", len(resp.Sessions))
	}
	if resp.Sessions[0].SessionId != uuid.MustParse(second.ID) {
		t.Fatalf("expected most recent session first")
	}
	if resp.Sessions[1].SessionId != uuid.MustParse(first.ID) {
		t.Fatalf("expected oldest session second")
	}
}

func TestListSessionsOrderAscLimitOffset(t *testing.T) {
	registry := session.NewRegistry(10, nil)

	first, err := registry.Create("alice", "SHA256:abc", "203.0.113.10", nil, nil)
	if err != nil {
		t.Fatalf("expected create to succeed: %v", err)
	}
	time.Sleep(2 * time.Millisecond)
	second, err := registry.Create("bob", "SHA256:def", "203.0.113.11", nil, nil)
	if err != nil {
		t.Fatalf("expected create to succeed: %v", err)
	}
	time.Sleep(2 * time.Millisecond)
	if _, err := registry.Create("carol", "SHA256:ghi", "203.0.113.12", nil, nil); err != nil {
		t.Fatalf("expected create to succeed: %v", err)
	}

	rec := performRequest(
		t,
		registry,
		http.MethodGet,
		"/api/v1/sessions?order_by=start_time%20asc&limit=1&offset=1",
	)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var resp SessionListResponse
	decodeJSON(t, rec, &resp)
	if len(resp.Sessions) != 1 {
		t.Fatalf("expected 1 session, got %d", len(resp.Sessions))
	}
	if resp.Sessions[0].SessionId != uuid.MustParse(second.ID) {
		t.Fatalf("expected second session in ascending order")
	}
	if resp.Sessions[0].SessionId == uuid.MustParse(first.ID) {
		t.Fatalf("expected offset to skip the first session")
	}
}

func TestListSessionsFiltersActive(t *testing.T) {
	registry := session.NewRegistry(10, nil)

	created, err := registry.Create("alice", "SHA256:abc", "203.0.113.10", nil, nil)
	if err != nil {
		t.Fatalf("expected create to succeed: %v", err)
	}
	_, _ = registry.Terminate(created.ID, session.TerminationReasonAdminTerminated)

	rec := performRequest(t, registry, http.MethodGet, "/api/v1/sessions")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var resp SessionListResponse
	decodeJSON(t, rec, &resp)
	if len(resp.Sessions) != 0 {
		t.Fatalf("expected 0 active sessions, got %d", len(resp.Sessions))
	}
}

func TestListSessionsInvalidLimit(t *testing.T) {
	registry := session.NewRegistry(10, nil)

	rec := performRequest(t, registry, http.MethodGet, "/api/v1/sessions?limit=0")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}

	var resp ErrorResponse
	decodeJSON(t, rec, &resp)
	if resp.Code != InvalidArgument {
		t.Fatalf("expected invalid_argument, got %s", resp.Code)
	}
	if resp.RequestId == "" {
		t.Fatalf("expected request_id to be set")
	}
	if resp.Details == nil || (*resp.Details)["field"] != "limit" {
		t.Fatalf("expected details.field to be limit")
	}
}

func TestGetSessionNotFound(t *testing.T) {
	registry := session.NewRegistry(10, nil)

	rec := performRequest(t, registry, http.MethodGet, "/api/v1/sessions/does-not-exist")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}

	var resp ErrorResponse
	decodeJSON(t, rec, &resp)
	if resp.Code != NotFound {
		t.Fatalf("expected not_found, got %s", resp.Code)
	}
}

func TestTerminateSession(t *testing.T) {
	registry := session.NewRegistry(10, nil)

	created, err := registry.Create("alice", "SHA256:abc", "203.0.113.10", nil, nil)
	if err != nil {
		t.Fatalf("expected create to succeed: %v", err)
	}

	rec := performRequest(t, registry, http.MethodPost, "/api/v1/sessions/"+created.ID+":terminate")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var resp Session
	decodeJSON(t, rec, &resp)
	if resp.State != Terminated {
		t.Fatalf("expected terminated state")
	}
	if resp.TerminationReason == nil || *resp.TerminationReason != AdminTerminated {
		t.Fatalf("expected admin_terminated reason")
	}
	if resp.EndTime == nil {
		t.Fatalf("expected end_time to be set")
	}

	recSecond := performRequest(
		t,
		registry,
		http.MethodPost,
		"/api/v1/sessions/"+created.ID+":terminate",
	)
	if recSecond.Code != http.StatusOK {
		t.Fatalf("expected 200 on idempotent terminate, got %d", recSecond.Code)
	}

	var respSecond Session
	decodeJSON(t, recSecond, &respSecond)
	if respSecond.State != Terminated {
		t.Fatalf("expected terminated state on idempotent call")
	}
	if respSecond.TerminationReason == nil || *respSecond.TerminationReason != AdminTerminated {
		t.Fatalf("expected admin_terminated reason on idempotent call")
	}
	if respSecond.EndTime == nil || !respSecond.EndTime.Equal(*resp.EndTime) {
		t.Fatalf("expected end_time to remain unchanged on idempotent call")
	}
}

func performRequest(
	t *testing.T,
	registry *session.Registry,
	method, path string,
) *httptest.ResponseRecorder {
	t.Helper()
	router := chi.NewRouter()
	New(registry, logging.NewTestLogger()).Register(router)

	req := httptest.NewRequest(method, path, nil)
	req.Header.Set(requestid.Header, "req-test")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func decodeJSON(t *testing.T, rec *httptest.ResponseRecorder, target any) {
	t.Helper()
	if err := json.NewDecoder(rec.Body).Decode(target); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
}
