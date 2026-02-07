package session

import (
	"testing"
	"time"

	"peertech.de/gate/internal/logging"
)

func TestLifecycleSweepTerminatesExpiredSessions(t *testing.T) {
	registry := NewRegistry(10, nil)

	created, err := registry.Create("alice", "SHA256:abc", "203.0.113.10", nil, nil)
	if err != nil {
		t.Fatalf("expected create to succeed: %v", err)
	}

	now := time.Now().UTC()
	registry.mu.Lock()
	registry.sessions[created.ID].session.StartTime = now.Add(-2 * time.Hour)
	registry.mu.Unlock()

	lifecycle := NewLifecycle(registry, time.Hour, logging.NewTestLogger())
	lifecycle.now = func() time.Time { return now }

	terminated := lifecycle.Sweep()
	if terminated != 1 {
		t.Fatalf("expected 1 terminated session, got %d", terminated)
	}

	record, ok := registry.Get(created.ID)
	if !ok {
		t.Fatalf("expected session to exist")
	}
	if record.State != StateTerminated {
		t.Fatalf("expected terminated state")
	}
	if record.TerminationReason != TerminationReasonMaxDuration {
		t.Fatalf("expected max_duration reason")
	}
}

func TestLifecycleSweepSkipsActiveSessions(t *testing.T) {
	registry := NewRegistry(10, nil)

	created, err := registry.Create("alice", "SHA256:abc", "203.0.113.10", nil, nil)
	if err != nil {
		t.Fatalf("expected create to succeed: %v", err)
	}

	now := time.Now().UTC()
	registry.mu.Lock()
	registry.sessions[created.ID].session.StartTime = now.Add(-30 * time.Minute)
	registry.mu.Unlock()

	lifecycle := NewLifecycle(registry, time.Hour, logging.NewTestLogger())
	lifecycle.now = func() time.Time { return now }

	terminated := lifecycle.Sweep()
	if terminated != 0 {
		t.Fatalf("expected 0 terminated sessions, got %d", terminated)
	}

	record, ok := registry.Get(created.ID)
	if !ok {
		t.Fatalf("expected session to exist")
	}
	if record.State != StateActive {
		t.Fatalf("expected session to remain active")
	}
}
