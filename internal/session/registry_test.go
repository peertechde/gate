package session

import "testing"

func TestRegistryCreateAndTerminate(t *testing.T) {
	registry := NewRegistry(10, nil)

	created, err := registry.Create(
		"alice",
		"SHA256:abc",
		"203.0.113.10",
		nil,
		func() error { return nil },
	)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if created.State != StateActive {
		t.Fatalf("expected active session")
	}

	terminated, ok := registry.Terminate(created.ID, TerminationReasonAdminTerminated)
	if !ok {
		t.Fatalf("expected session to exist")
	}
	if terminated.State != StateTerminated {
		t.Fatalf("expected terminated state")
	}
	if terminated.TerminationReason != TerminationReasonAdminTerminated {
		t.Fatalf("expected termination reason to be set")
	}
}

func TestRegistryMaxSessions(t *testing.T) {
	registry := NewRegistry(1, nil)
	if _, err := registry.Create(
		"alice",
		"SHA256:abc",
		"203.0.113.10",
		nil,
		func() error { return nil },
	); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if _, err := registry.Create(
		"bob",
		"SHA256:def",
		"203.0.113.11",
		nil,
		func() error { return nil },
	); err != ErrMaxSessionsExceeded {
		t.Fatalf("expected max sessions error, got %v", err)
	}
}

func TestRegistryTerminateByUser(t *testing.T) {
	registry := NewRegistry(10, nil)

	alice, err := registry.Create(
		"alice",
		"SHA256:abc",
		"203.0.113.10",
		nil,
		func() error { return nil },
	)
	if err != nil {
		t.Fatalf("expected create to succeed: %v", err)
	}
	bob, err := registry.Create(
		"bob",
		"SHA256:def",
		"203.0.113.11",
		nil,
		func() error { return nil },
	)
	if err != nil {
		t.Fatalf("expected create to succeed: %v", err)
	}

	terminated := registry.TerminateByUser("alice", TerminationReasonRevoked)
	if terminated != 1 {
		t.Fatalf("expected 1 terminated session, got %d", terminated)
	}

	record, ok := registry.Get(alice.ID)
	if !ok {
		t.Fatalf("expected alice session to exist")
	}
	if record.State != StateTerminated {
		t.Fatalf("expected alice session to be terminated")
	}

	record, ok = registry.Get(bob.ID)
	if !ok {
		t.Fatalf("expected bob session to exist")
	}
	if record.State != StateActive {
		t.Fatalf("expected bob session to remain active")
	}

	terminated = registry.TerminateByUser("alice", TerminationReasonRevoked)
	if terminated != 0 {
		t.Fatalf("expected 0 terminated sessions on idempotent call, got %d", terminated)
	}
}

func TestRegistryTerminateAll(t *testing.T) {
	registry := NewRegistry(10, nil)

	if _, err := registry.Create(
		"alice",
		"SHA256:abc",
		"203.0.113.10",
		nil,
		func() error { return nil },
	); err != nil {
		t.Fatalf("expected create to succeed: %v", err)
	}
	if _, err := registry.Create(
		"bob",
		"SHA256:def",
		"203.0.113.11",
		nil,
		func() error { return nil },
	); err != nil {
		t.Fatalf("expected create to succeed: %v", err)
	}

	terminated := registry.TerminateAll(TerminationReasonError)
	if terminated != 2 {
		t.Fatalf("expected 2 terminated sessions, got %d", terminated)
	}

	terminated = registry.TerminateAll(TerminationReasonError)
	if terminated != 0 {
		t.Fatalf("expected 0 terminated sessions on idempotent call, got %d", terminated)
	}
}
