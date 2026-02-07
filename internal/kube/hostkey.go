package kube

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"golang.org/x/crypto/ssh"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

var ErrHostKeyMissing = errors.New("host key secret missing")

// HostKeyOptions configures host key loading from Kubernetes Secrets.
type HostKeyOptions struct {
	SecretName      string
	SecretNamespace string
	SecretKey       string
	Bootstrap       bool
	Timeout         time.Duration
}

// HostKeyLoader loads or bootstraps the SSH host key from a Secret.
type HostKeyLoader struct {
	client kubernetes.Interface
	opts   HostKeyOptions
	logger *slog.Logger
}

func NewHostKeyLoader(
	client kubernetes.Interface,
	opts HostKeyOptions,
	logger *slog.Logger,
) *HostKeyLoader {
	return &HostKeyLoader{
		client: client,
		opts:   opts,
		logger: logger,
	}
}

// Load returns an SSH signer loaded from the Secret or bootstrapped if enabled.
func (l *HostKeyLoader) Load(ctx context.Context) (ssh.Signer, error) {
	secret, err := l.getSecret(ctx)
	if err != nil {
		if apierrors.IsNotFound(err) {
			if !l.opts.Bootstrap {
				return nil, ErrHostKeyMissing
			}
			return l.bootstrap(ctx)
		}
		return nil, fmt.Errorf("get host key secret: %w", err)
	}

	return signerFromSecret(secret, l.opts.SecretKey)
}

func (l *HostKeyLoader) bootstrap(ctx context.Context) (ssh.Signer, error) {
	keyBytes, err := generatePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("generate host key: %w", err)
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      l.opts.SecretName,
			Namespace: l.opts.SecretNamespace,
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			l.opts.SecretKey: keyBytes,
		},
	}

	createCtx, cancel := context.WithTimeout(ctx, l.opts.Timeout)
	defer cancel()

	created, err := l.client.CoreV1().
		Secrets(l.opts.SecretNamespace).
		Create(createCtx, secret, metav1.CreateOptions{})
	if err != nil {
		if apierrors.IsAlreadyExists(err) {
			secret, err = l.getSecret(ctx)
			if err != nil {
				return nil, fmt.Errorf("get existing host key secret: %w", err)
			}
			return signerFromSecret(secret, l.opts.SecretKey)
		}
		return nil, fmt.Errorf("create host key secret: %w", err)
	}

	l.logger.Info(
		"host key secret created",
		"name",
		l.opts.SecretName,
		"namespace",
		l.opts.SecretNamespace,
	)

	return signerFromSecret(created, l.opts.SecretKey)
}

func (l *HostKeyLoader) getSecret(ctx context.Context) (*corev1.Secret, error) {
	getCtx, cancel := context.WithTimeout(ctx, l.opts.Timeout)
	defer cancel()

	return l.client.CoreV1().
		Secrets(l.opts.SecretNamespace).
		Get(getCtx, l.opts.SecretName, metav1.GetOptions{})
}

func signerFromSecret(secret *corev1.Secret, key string) (ssh.Signer, error) {
	if secret == nil {
		return nil, ErrHostKeyMissing
	}
	data, ok := secret.Data[key]
	if !ok || len(data) == 0 {
		return nil, fmt.Errorf("host key secret missing data for key %q", key)
	}
	return ssh.ParsePrivateKey(data)
}

func generatePrivateKey() ([]byte, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	encoded, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}

	block := &pem.Block{Type: "PRIVATE KEY", Bytes: encoded}
	return pem.EncodeToMemory(block), nil
}
