package sshserver

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"peertech.de/gate/internal/kube"
	"peertech.de/gate/internal/logging"
	"peertech.de/gate/internal/session"
)

func TestResolveDestination(t *testing.T) {
	cfg := Config{
		AllowedHost:    "kube-api.example.com",
		AllowedPort:    443,
		AllowedAliases: []string{"api", "kubernetes.default.svc."},
	}
	server := New(cfg, nil, nil, nil, logging.NewTestLogger())

	t.Run("exact host accepted", func(t *testing.T) {
		host, port, aliasUsed, ok := server.resolveDestination("kube-api.example.com", 443)
		if !ok {
			t.Fatalf("expected destination to be allowed")
		}
		if aliasUsed {
			t.Fatalf("expected aliasUsed=false")
		}
		if host != cfg.AllowedHost || port != cfg.AllowedPort {
			t.Fatalf("unexpected resolved destination %s:%d", host, port)
		}
	})

	t.Run("alias accepted", func(t *testing.T) {
		host, port, aliasUsed, ok := server.resolveDestination("api", 443)
		if !ok {
			t.Fatalf("expected alias destination to be allowed")
		}
		if !aliasUsed {
			t.Fatalf("expected aliasUsed=true")
		}
		if host != cfg.AllowedHost || port != cfg.AllowedPort {
			t.Fatalf("unexpected resolved destination %s:%d", host, port)
		}
	})

	t.Run("alias wrong port rejected", func(t *testing.T) {
		_, _, _, ok := server.resolveDestination("api", 6443)
		if ok {
			t.Fatalf("expected alias with wrong port to be rejected")
		}
	})

	t.Run("unknown host rejected", func(t *testing.T) {
		_, _, _, ok := server.resolveDestination("db", 443)
		if ok {
			t.Fatalf("expected unknown host to be rejected")
		}
	})

	t.Run("alias normalization", func(t *testing.T) {
		host, port, aliasUsed, ok := server.resolveDestination("KUBERNETES.DEFAULT.SVC.", 443)
		if !ok {
			t.Fatalf("expected normalized alias to be allowed")
		}
		if !aliasUsed {
			t.Fatalf("expected aliasUsed=true")
		}
		if host != cfg.AllowedHost || port != cfg.AllowedPort {
			t.Fatalf("unexpected resolved destination %s:%d", host, port)
		}
	})
}

type fakeUserCache struct {
	record kube.UserRecord
	ok     bool
	err    error
}

func (f fakeUserCache) LookupByUserName(
	_ context.Context,
	_ string,
) (kube.UserRecord, bool, error) {
	if f.err != nil {
		return kube.UserRecord{}, false, f.err
	}
	if !f.ok {
		return kube.UserRecord{}, false, nil
	}
	return f.record, true, nil
}

func TestPublicKeyCallbackUserNameAndKey(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	pubKey := signer.PublicKey()
	fingerprint := ssh.FingerprintSHA256(pubKey)
	authorizedKey := string(ssh.MarshalAuthorizedKey(pubKey))

	server := New(
		Config{},
		nil,
		fakeUserCache{
			ok: true,
			record: kube.UserRecord{
				UserName:   "alice",
				PublicKeys: []string{authorizedKey},
				Enabled:    true,
			},
		},
		nil,
		logging.NewTestLogger(),
	)

	permissions, err := server.publicKeyCallback(context.Background())(
		fakeConnMetadata{user: "alice"},
		pubKey,
	)
	if err != nil {
		t.Fatalf("expected auth to succeed: %v", err)
	}
	if permissions == nil {
		t.Fatalf("expected permissions to be set")
	}
	if permissions.Extensions["user_name"] != "alice" {
		t.Fatalf("expected user_name extension")
	}
	if permissions.Extensions["fingerprint"] != fingerprint {
		t.Fatalf("expected fingerprint extension")
	}
}

func TestPublicKeyCallbackUserNameMismatchKey(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	_, otherPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	otherSigner, err := ssh.NewSignerFromKey(otherPriv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	authorizedKey := string(ssh.MarshalAuthorizedKey(otherSigner.PublicKey()))

	server := New(
		Config{},
		nil,
		fakeUserCache{
			ok: true,
			record: kube.UserRecord{
				UserName:   "alice",
				PublicKeys: []string{authorizedKey},
				Enabled:    true,
			},
		},
		nil,
		logging.NewTestLogger(),
	)

	_, err = server.publicKeyCallback(context.Background())(
		fakeConnMetadata{user: "alice"},
		signer.PublicKey(),
	)
	if err == nil {
		t.Fatalf("expected auth to be denied")
	}
}

func TestPublicKeyCallbackMissingUser(t *testing.T) {
	server := New(Config{}, nil, fakeUserCache{ok: false}, nil, logging.NewTestLogger())
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	_, err = server.publicKeyCallback(context.Background())(
		fakeConnMetadata{user: "alice"},
		signer.PublicKey(),
	)
	if err == nil {
		t.Fatalf("expected auth to be denied")
	}
}

func TestPublicKeyCallbackCacheError(t *testing.T) {
	cacheErr := errors.New("cache unavailable")
	server := New(Config{}, nil, fakeUserCache{err: cacheErr}, nil, logging.NewTestLogger())
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	_, err = server.publicKeyCallback(context.Background())(
		fakeConnMetadata{user: "alice"},
		signer.PublicKey(),
	)
	if !errors.Is(err, cacheErr) {
		t.Fatalf("expected cache error, got %v", err)
	}
}

func TestPublicKeyCallbackMissingUserName(t *testing.T) {
	server := New(Config{}, nil, fakeUserCache{ok: true}, nil, logging.NewTestLogger())
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	_, err = server.publicKeyCallback(context.Background())(
		fakeConnMetadata{user: ""},
		signer.PublicKey(),
	)
	if err == nil {
		t.Fatalf("expected error for missing username")
	}
}

func TestDrainCompletesWhenSessionsTerminate(t *testing.T) {
	registry := session.NewRegistry(10, nil)
	created, err := registry.Create(
		"alice",
		"SHA256:abc",
		"203.0.113.10",
		nil,
		nil,
	)
	if err != nil {
		t.Fatalf("expected create to succeed: %v", err)
	}

	server := &Server{sessions: registry, logger: logging.NewTestLogger()}
	done := make(chan int, 1)
	go func() {
		done <- server.Drain(500 * time.Millisecond)
	}()

	time.Sleep(50 * time.Millisecond)
	_, _ = registry.Terminate(created.ID, session.TerminationReasonAdminTerminated)

	select {
	case remaining := <-done:
		if remaining != 0 {
			t.Fatalf("expected 0 remaining sessions, got %d", remaining)
		}
	case <-time.After(time.Second):
		t.Fatalf("expected drain to complete")
	}
}

func TestDrainTimesOutWithActiveSessions(t *testing.T) {
	registry := session.NewRegistry(10, nil)
	if _, err := registry.Create(
		"alice",
		"SHA256:abc",
		"203.0.113.10",
		nil,
		nil,
	); err != nil {
		t.Fatalf("expected create to succeed: %v", err)
	}

	server := &Server{sessions: registry, logger: logging.NewTestLogger()}
	remaining := server.Drain(100 * time.Millisecond)
	if remaining != 1 {
		t.Fatalf("expected 1 remaining session, got %d", remaining)
	}
}

type fakeConnMetadata struct {
	user string
}

func (f fakeConnMetadata) User() string {
	return f.user
}

func (f fakeConnMetadata) SessionID() []byte {
	return nil
}

func (f fakeConnMetadata) ClientVersion() []byte {
	return nil
}

func (f fakeConnMetadata) ServerVersion() []byte {
	return nil
}

func (f fakeConnMetadata) RemoteAddr() net.Addr {
	return nil
}

func (f fakeConnMetadata) LocalAddr() net.Addr {
	return nil
}
