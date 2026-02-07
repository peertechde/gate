package config

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	HTTP      HTTPConfig
	Metrics   MetricsConfig
	Logging   LoggingConfig
	Kube      KubeConfig
	HostKey   HostKeyConfig
	SSH       SSHConfig
	OIDC      OIDCConfig
	APIServer APIServerConfig
	Limits    LimitsConfig
}

// HTTPConfig configures the control HTTP server.
type HTTPConfig struct {
	Address           string
	ReadTimeout       time.Duration
	ReadHeaderTimeout time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	RequestTimeout    time.Duration
	StopTimeout       time.Duration
}

type MetricsConfig struct {
	Enabled bool
}

type LoggingConfig struct {
	Level string
}

// KubeConfig controls Kubernetes client behavior.
type KubeConfig struct {
	Kubeconfig        string
	QPS               float64
	Burst             int
	Timeout           time.Duration
	CacheSyncTimeout  time.Duration
	CacheResyncPeriod time.Duration
	UserNamespace     string
}

// HostKeyConfig controls host key loading from Kubernetes Secrets.
type HostKeyConfig struct {
	SecretName      string
	SecretNamespace string
	SecretKey       string
	Bootstrap       bool
}

// SSHConfig controls the SSH server.
type SSHConfig struct {
	Address     string
	AuthTimeout time.Duration
	DialTimeout time.Duration
	StopTimeout time.Duration
}

// OIDCConfig controls optional OIDC device-flow authentication.
type OIDCConfig struct {
	IssuerURL     string
	ClientID      string
	ClientSecret  string
	Scopes        []string
	GroupClaim    string
	DeviceTimeout time.Duration
	HTTPTimeout   time.Duration
}

// APIServerConfig controls the allowlisted API server endpoint.
type APIServerConfig struct {
	Host string
	Port int
	// AllowedAliases are optional hostnames accepted for SSH port forwarding.
	AllowedAliases []string
}

// LimitsConfig controls global session limits.
type LimitsConfig struct {
	MaxConcurrentSessions int
	MaxSessionDuration    time.Duration
}

// Default returns the default configuration.
func Default() Config {
	return Config{
		HTTP: HTTPConfig{
			Address:           ":8080",
			ReadTimeout:       5 * time.Second,
			ReadHeaderTimeout: 5 * time.Second,
			WriteTimeout:      10 * time.Second,
			IdleTimeout:       30 * time.Second,
			RequestTimeout:    10 * time.Second,
			StopTimeout:       10 * time.Second,
		},
		Metrics: MetricsConfig{
			Enabled: true,
		},
		Logging: LoggingConfig{
			Level: "info",
		},
		Kube: KubeConfig{
			QPS:               5,
			Burst:             10,
			Timeout:           5 * time.Second,
			CacheSyncTimeout:  10 * time.Second,
			CacheResyncPeriod: 10 * time.Minute,
			UserNamespace:     defaultNamespace(),
		},
		HostKey: HostKeyConfig{
			SecretName:      "gate-host-key",
			SecretNamespace: defaultNamespace(),
			SecretKey:       "ssh_host_key",
			Bootstrap:       false,
		},
		SSH: SSHConfig{
			Address:     ":2222",
			AuthTimeout: 10 * time.Second,
			DialTimeout: 10 * time.Second,
			StopTimeout: 10 * time.Second,
		},
		OIDC: OIDCConfig{
			Scopes:        []string{"openid", "profile", "email"},
			GroupClaim:    "groups",
			DeviceTimeout: 2 * time.Minute,
			HTTPTimeout:   5 * time.Second,
		},
		APIServer: APIServerConfig{
			Host:           defaultAPIServerHost(),
			Port:           defaultAPIServerPort(),
			AllowedAliases: defaultAPIServerAliases(),
		},
		Limits: LimitsConfig{
			MaxConcurrentSessions: 100,
			MaxSessionDuration:    0,
		},
	}
}

// Load parses flags from the default flagset.
func Load() (Config, error) {
	return Parse(flag.CommandLine, os.Args[1:])
}

// Parse parses configuration from the provided FlagSet and args.
func Parse(fs *flag.FlagSet, args []string) (Config, error) {
	cfg := Default()

	fs.StringVar(&cfg.HTTP.Address, "http-address", cfg.HTTP.Address, "HTTP listen address")
	fs.DurationVar(
		&cfg.HTTP.ReadTimeout,
		"http-read-timeout",
		cfg.HTTP.ReadTimeout,
		"HTTP read timeout",
	)
	fs.DurationVar(
		&cfg.HTTP.ReadHeaderTimeout,
		"http-read-header-timeout",
		cfg.HTTP.ReadHeaderTimeout,
		"HTTP read header timeout",
	)
	fs.DurationVar(
		&cfg.HTTP.WriteTimeout,
		"http-write-timeout",
		cfg.HTTP.WriteTimeout,
		"HTTP write timeout",
	)
	fs.DurationVar(
		&cfg.HTTP.IdleTimeout,
		"http-idle-timeout",
		cfg.HTTP.IdleTimeout,
		"HTTP idle timeout",
	)
	fs.DurationVar(
		&cfg.HTTP.RequestTimeout,
		"http-request-timeout",
		cfg.HTTP.RequestTimeout,
		"Per-request timeout for HTTP handlers",
	)
	fs.DurationVar(
		&cfg.HTTP.StopTimeout,
		"http-stop-timeout",
		cfg.HTTP.StopTimeout,
		"HTTP server graceful stop timeout",
	)
	fs.BoolVar(
		&cfg.Metrics.Enabled,
		"metrics-enabled",
		cfg.Metrics.Enabled,
		"Enable /metrics endpoint",
	)
	fs.StringVar(
		&cfg.Logging.Level,
		"log-level",
		cfg.Logging.Level,
		"Log level (debug, info, warn, error)",
	)
	fs.StringVar(
		&cfg.Kube.Kubeconfig,
		"kubeconfig",
		cfg.Kube.Kubeconfig,
		"Path to kubeconfig file (out-of-cluster only)",
	)
	fs.Float64Var(
		&cfg.Kube.QPS,
		"kube-qps",
		cfg.Kube.QPS,
		"Kubernetes client QPS",
	)
	fs.IntVar(
		&cfg.Kube.Burst,
		"kube-burst",
		cfg.Kube.Burst,
		"Kubernetes client burst",
	)
	fs.DurationVar(
		&cfg.Kube.Timeout,
		"kube-timeout",
		cfg.Kube.Timeout,
		"Kubernetes API call timeout",
	)
	fs.DurationVar(
		&cfg.Kube.CacheSyncTimeout,
		"kube-cache-sync-timeout",
		cfg.Kube.CacheSyncTimeout,
		"User CRD cache sync timeout",
	)
	fs.DurationVar(
		&cfg.Kube.CacheResyncPeriod,
		"kube-cache-resync-period",
		cfg.Kube.CacheResyncPeriod,
		"User CRD cache resync period",
	)
	fs.StringVar(
		&cfg.Kube.UserNamespace,
		"user-namespace",
		cfg.Kube.UserNamespace,
		"Namespace to watch for User CRDs",
	)
	fs.StringVar(
		&cfg.HostKey.SecretName,
		"hostkey-secret-name",
		cfg.HostKey.SecretName,
		"Name of the Kubernetes Secret containing the SSH host key",
	)
	fs.StringVar(
		&cfg.HostKey.SecretNamespace,
		"hostkey-secret-namespace",
		cfg.HostKey.SecretNamespace,
		"Namespace of the Kubernetes Secret containing the SSH host key",
	)
	fs.StringVar(
		&cfg.HostKey.SecretKey,
		"hostkey-secret-key",
		cfg.HostKey.SecretKey,
		"Key within the Secret data holding the SSH host key",
	)
	fs.BoolVar(
		&cfg.HostKey.Bootstrap,
		"hostkey-bootstrap",
		cfg.HostKey.Bootstrap,
		"Generate and store a host key if the Secret is missing",
	)
	fs.StringVar(
		&cfg.SSH.Address,
		"ssh-address",
		cfg.SSH.Address,
		"SSH listen address",
	)
	fs.DurationVar(
		&cfg.SSH.AuthTimeout,
		"ssh-auth-timeout",
		cfg.SSH.AuthTimeout,
		"SSH authentication timeout",
	)
	fs.DurationVar(
		&cfg.SSH.DialTimeout,
		"ssh-dial-timeout",
		cfg.SSH.DialTimeout,
		"Timeout for TCP dial to the Kubernetes API server",
	)
	fs.DurationVar(
		&cfg.SSH.StopTimeout,
		"ssh-stop-timeout",
		cfg.SSH.StopTimeout,
		"SSH server drain timeout on shutdown",
	)
	fs.StringVar(
		&cfg.OIDC.IssuerURL,
		"oidc-issuer-url",
		cfg.OIDC.IssuerURL,
		"OIDC issuer URL for device-flow SSO",
	)
	fs.StringVar(
		&cfg.OIDC.ClientID,
		"oidc-client-id",
		cfg.OIDC.ClientID,
		"OIDC client ID for device-flow SSO",
	)
	fs.StringVar(
		&cfg.OIDC.ClientSecret,
		"oidc-client-secret",
		cfg.OIDC.ClientSecret,
		"OIDC client secret for device-flow SSO (optional)",
	)
	oidcScopes := strings.Join(cfg.OIDC.Scopes, ",")
	fs.StringVar(
		&oidcScopes,
		"oidc-scopes",
		oidcScopes,
		"Comma-separated OIDC scopes for device-flow SSO",
	)
	fs.StringVar(
		&cfg.OIDC.GroupClaim,
		"oidc-group-claim",
		cfg.OIDC.GroupClaim,
		"OIDC claim name containing groups (default: groups)",
	)
	fs.DurationVar(
		&cfg.OIDC.DeviceTimeout,
		"oidc-device-timeout",
		cfg.OIDC.DeviceTimeout,
		"Maximum duration for OIDC device-flow authentication",
	)
	fs.DurationVar(
		&cfg.OIDC.HTTPTimeout,
		"oidc-http-timeout",
		cfg.OIDC.HTTPTimeout,
		"Timeout for OIDC HTTP requests",
	)
	fs.StringVar(
		&cfg.APIServer.Host,
		"api-server-host",
		cfg.APIServer.Host,
		"Kubernetes API server host allowlist",
	)
	fs.IntVar(
		&cfg.APIServer.Port,
		"api-server-port",
		cfg.APIServer.Port,
		"Kubernetes API server port allowlist",
	)
	aliases := strings.Join(cfg.APIServer.AllowedAliases, ",")
	fs.StringVar(
		&aliases,
		"api-server-aliases",
		aliases,
		"Comma-separated SSH port-forward host aliases for the API server",
	)
	fs.IntVar(
		&cfg.Limits.MaxConcurrentSessions,
		"max-concurrent-sessions",
		cfg.Limits.MaxConcurrentSessions,
		"Maximum number of concurrent SSH sessions",
	)
	fs.DurationVar(
		&cfg.Limits.MaxSessionDuration,
		"max-session-duration",
		cfg.Limits.MaxSessionDuration,
		"Maximum lifetime of a session (0 disables enforcement)",
	)

	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}

	cfg.APIServer.AllowedAliases = parseCommaList(aliases)
	cfg.OIDC.Scopes = parseCommaList(oidcScopes)

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

func (c *Config) Validate() error {
	// HTTP
	if c.HTTP.Address == "" {
		return fmt.Errorf("http address must not be empty")
	}
	if err := validatePositiveDuration("http-read-timeout", c.HTTP.ReadTimeout); err != nil {
		return err
	}
	if err := validatePositiveDuration(
		"http-read-header-timeout",
		c.HTTP.ReadHeaderTimeout,
	); err != nil {
		return err
	}
	if err := validatePositiveDuration("http-write-timeout", c.HTTP.WriteTimeout); err != nil {
		return err
	}
	if err := validatePositiveDuration("http-idle-timeout", c.HTTP.IdleTimeout); err != nil {
		return err
	}
	if err := validatePositiveDuration("http-request-timeout", c.HTTP.RequestTimeout); err != nil {
		return err
	}
	if err := validatePositiveDuration(
		"http-stop-timeout",
		c.HTTP.StopTimeout,
	); err != nil {
		return err
	}

	// Logging
	if err := validateLogLevel(c.Logging.Level); err != nil {
		return err
	}

	// Kube
	if c.Kube.QPS <= 0 {
		return fmt.Errorf("kube-qps must be positive")
	}
	if c.Kube.Burst < 0 {
		return fmt.Errorf("kube-burst must be non-negative")
	}
	if err := validatePositiveDuration("kube-timeout", c.Kube.Timeout); err != nil {
		return err
	}
	if err := validatePositiveDuration(
		"kube-cache-sync-timeout",
		c.Kube.CacheSyncTimeout,
	); err != nil {
		return err
	}
	if err := validatePositiveDuration(
		"kube-cache-resync-period",
		c.Kube.CacheResyncPeriod,
	); err != nil {
		return err
	}
	if c.Kube.UserNamespace == "" {
		return fmt.Errorf("user-namespace must not be empty")
	}

	// HostKey
	if c.HostKey.SecretName == "" {
		return fmt.Errorf("hostkey-secret-name must not be empty")
	}
	if c.HostKey.SecretNamespace == "" {
		return fmt.Errorf("hostkey-secret-namespace must not be empty")
	}
	if c.HostKey.SecretKey == "" {
		return fmt.Errorf("hostkey-secret-key must not be empty")
	}

	// SSH
	if c.SSH.Address == "" {
		return fmt.Errorf("ssh-address must not be empty")
	}
	if err := validatePositiveDuration("ssh-auth-timeout", c.SSH.AuthTimeout); err != nil {
		return err
	}
	if err := validatePositiveDuration("ssh-dial-timeout", c.SSH.DialTimeout); err != nil {
		return err
	}
	if err := validatePositiveDuration("ssh-stop-timeout", c.SSH.StopTimeout); err != nil {
		return err
	}

	// OIDC
	if c.OIDC.Enabled() {
		if c.OIDC.IssuerURL == "" || c.OIDC.ClientID == "" {
			return fmt.Errorf("oidc-issuer-url and oidc-client-id must be set together")
		}
		if err := validatePositiveDuration(
			"oidc-device-timeout",
			c.OIDC.DeviceTimeout,
		); err != nil {
			return err
		}
		if err := validatePositiveDuration("oidc-http-timeout", c.OIDC.HTTPTimeout); err != nil {
			return err
		}
		if len(c.OIDC.Scopes) == 0 {
			return fmt.Errorf("oidc-scopes must not be empty")
		}
		if strings.TrimSpace(c.OIDC.GroupClaim) == "" {
			return fmt.Errorf("oidc-group-claim must not be empty")
		}

	}

	// APIServer
	if c.APIServer.Host == "" {
		return fmt.Errorf("api-server-host must not be empty")
	}
	if c.APIServer.Port <= 0 {
		return fmt.Errorf("api-server-port must be positive")
	}

	// Limits
	if c.Limits.MaxConcurrentSessions <= 0 {
		return fmt.Errorf("max-concurrent-sessions must be positive")
	}
	if err := validateNonNegativeDuration(
		"max-session-duration",
		c.Limits.MaxSessionDuration,
	); err != nil {
		return err
	}

	return nil
}

// Enabled reports whether OIDC configuration is present.
func (c OIDCConfig) Enabled() bool {
	return c.IssuerURL != "" && c.ClientID != ""
}

func validatePositiveDuration(name string, value time.Duration) error {
	if value <= 0 {
		return fmt.Errorf("%s must be positive", name)
	}

	return nil
}

func validateNonNegativeDuration(name string, value time.Duration) error {
	if value < 0 {
		return fmt.Errorf("%s must not be negative", name)
	}

	return nil
}

func validateLogLevel(level string) error {
	switch level {
	case "debug", "info", "warn", "error":
		return nil
	default:
		return fmt.Errorf("log-level must be one of debug, info, warn, error")
	}
}

func defaultNamespace() string {
	if value := os.Getenv("POD_NAMESPACE"); value != "" {
		return value
	}

	data, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
	if err != nil {
		return ""
	}

	return string(bytes.TrimSpace(data))
}

func defaultAPIServerHost() string {
	return os.Getenv("KUBERNETES_SERVICE_HOST")
}

func defaultAPIServerPort() int {
	value := os.Getenv("KUBERNETES_SERVICE_PORT")
	if value == "" {
		return 0
	}

	port, err := strconv.Atoi(value)
	if err != nil {
		return 0
	}

	return port
}

func defaultAPIServerAliases() []string {
	return []string{
		"apiserver",
		"kubernetes",
		"kube-apiserver",
		"kubernetes.default",
		"kubernetes.default.svc",
		"kubernetes.default.svc.cluster.local",
	}
}

func parseCommaList(value string) []string {
	if value == "" {
		return nil
	}

	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		item := strings.TrimSpace(part)
		if item == "" {
			continue
		}
		out = append(out, item)
	}

	return out
}
