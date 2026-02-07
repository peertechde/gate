package kube

import (
	"context"
	"errors"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"peertech.de/gate/internal/logging"
)

func TestHostKeyLoadExisting(t *testing.T) {
	keyBytes, err := generatePrivateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	client := fake.NewSimpleClientset(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "gate-host-key",
			Namespace: "gate",
		},
		Data: map[string][]byte{
			"ssh_host_key": keyBytes,
		},
	})

	loader := NewHostKeyLoader(client, HostKeyOptions{
		SecretName:      "gate-host-key",
		SecretNamespace: "gate",
		SecretKey:       "ssh_host_key",
		Bootstrap:       false,
		Timeout:         2 * time.Second,
	}, logging.NewTestLogger())

	signer, err := loader.Load(context.Background())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if signer == nil {
		t.Fatalf("expected signer, got nil")
	}
}

func TestHostKeyBootstrap(t *testing.T) {
	client := fake.NewSimpleClientset()

	loader := NewHostKeyLoader(client, HostKeyOptions{
		SecretName:      "gate-host-key",
		SecretNamespace: "gate",
		SecretKey:       "ssh_host_key",
		Bootstrap:       true,
		Timeout:         2 * time.Second,
	}, logging.NewTestLogger())

	signer, err := loader.Load(context.Background())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if signer == nil {
		t.Fatalf("expected signer, got nil")
	}

	secret, err := client.CoreV1().
		Secrets("gate").
		Get(context.Background(), "gate-host-key", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("expected secret to be created, got %v", err)
	}

	data, ok := secret.Data["ssh_host_key"]
	if !ok || len(data) == 0 {
		t.Fatalf("expected host key data in secret")
	}

	if _, err := ssh.ParsePrivateKey(data); err != nil {
		t.Fatalf("expected secret to contain valid key, got %v", err)
	}
}

func TestHostKeyMissingWithoutBootstrap(t *testing.T) {
	client := fake.NewSimpleClientset()

	loader := NewHostKeyLoader(client, HostKeyOptions{
		SecretName:      "gate-host-key",
		SecretNamespace: "gate",
		SecretKey:       "ssh_host_key",
		Bootstrap:       false,
		Timeout:         2 * time.Second,
	}, logging.NewTestLogger())

	_, err := loader.Load(context.Background())
	if !errors.Is(err, ErrHostKeyMissing) {
		t.Fatalf("expected ErrHostKeyMissing, got %v", err)
	}
}

func TestHostKeyInvalidSecretData(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "gate-host-key",
			Namespace: "gate",
		},
		Data: map[string][]byte{
			"ssh_host_key": []byte("not-a-valid-key"),
		},
	})

	loader := NewHostKeyLoader(client, HostKeyOptions{
		SecretName:      "gate-host-key",
		SecretNamespace: "gate",
		SecretKey:       "ssh_host_key",
		Bootstrap:       false,
		Timeout:         2 * time.Second,
	}, logging.NewTestLogger())

	_, err := loader.Load(context.Background())
	if err == nil {
		t.Fatalf("expected error for invalid key data")
	}
	if errors.Is(err, ErrHostKeyMissing) {
		t.Fatalf("expected parse error, got ErrHostKeyMissing")
	}
}
