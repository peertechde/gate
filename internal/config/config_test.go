package config

import (
	"flag"
	"testing"
	"time"
)

func TestParseDefaults(t *testing.T) {
	t.Setenv("POD_NAMESPACE", "test-ns")
	t.Setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
	t.Setenv("KUBERNETES_SERVICE_PORT", "6443")
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	cfg, err := Parse(fs, []string{})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if cfg.HTTP.Address == "" {
		t.Fatalf("expected default http address")
	}
	if cfg.Logging.Level == "" {
		t.Fatalf("expected default log level")
	}
	if cfg.Kube.UserNamespace == "" {
		t.Fatalf("expected default user namespace")
	}
	if cfg.APIServer.Host == "" || cfg.APIServer.Port == 0 {
		t.Fatalf("expected api server defaults")
	}
}

func TestValidate(t *testing.T) {
	t.Setenv("POD_NAMESPACE", "test-ns")
	t.Setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
	t.Setenv("KUBERNETES_SERVICE_PORT", "6443")
	cfg := Default()
	cfg.HTTP.Address = ""
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected error for empty address")
	}

	cfg = Default()
	cfg.HTTP.ReadTimeout = 0
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected error for non-positive read timeout")
	}

	cfg = Default()
	cfg.Logging.Level = "nope"
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected error for invalid log level")
	}

	cfg = Default()
	cfg.HTTP.RequestTimeout = 2 * time.Second
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected config to be valid, got %v", err)
	}

	cfg = Default()
	cfg.SSH.StopTimeout = 0
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected error for ssh stop timeout")
	}

	cfg = Default()
	cfg.Kube.UserNamespace = ""
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected error for empty user namespace")
	}

	cfg = Default()
	cfg.APIServer.Host = ""
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected error for empty api server host")
	}

	cfg = Default()
	cfg.APIServer.Port = 0
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected error for empty api server port")
	}

	cfg = Default()
	cfg.Limits.MaxConcurrentSessions = 0
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected error for max sessions")
	}

	cfg = Default()
	cfg.Limits.MaxSessionDuration = -time.Second
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected error for negative max session duration")
	}

	cfg = Default()
	cfg.Limits.MaxSessionDuration = 0
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected zero max session duration to be allowed, got %v", err)
	}
}
