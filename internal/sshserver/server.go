package sshserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"peertech.de/gate/internal/kube"
	"peertech.de/gate/internal/metrics"
	"peertech.de/gate/internal/oidc"
	"peertech.de/gate/internal/session"
)

// Config controls the SSH server behavior.
type Config struct {
	// Address is the TCP listen address for the SSH server.
	Address string
	// AuthTimeout caps the duration for SSH authentication.
	AuthTimeout time.Duration
	// DialTimeout caps the TCP dial time to the API server.
	DialTimeout time.Duration
	// StopTimeout caps the duration to drain active sessions on shutdown.
	StopTimeout time.Duration
	// AllowedHost is the canonical Kubernetes API server host to dial.
	AllowedHost string
	// AllowedPort is the canonical Kubernetes API server port to dial.
	AllowedPort int
	// AllowedAliases are optional hostnames accepted for SSH port forwarding,
	// which are rewritten to AllowedHost:AllowedPort.
	AllowedAliases []string
	// OIDC provides optional OIDC device-flow authentication.
	OIDC *oidc.Authenticator
	// Metrics allows SSH transport metrics to be recorded.
	Metrics *metrics.Registry
}

// Server implements the Gate SSH listener.
type Server struct {
	cfg       Config
	userCache userLookup
	sessions  *session.Registry
	logger    *slog.Logger
	ln        net.Listener
	signer    ssh.Signer
	aliases   map[string]struct{}
	hostKey   string
	oidcAuth  *oidc.Authenticator
	metrics   *metrics.Registry
}

type userLookup interface {
	LookupByUserName(context.Context, string) (kube.UserRecord, bool, error)
}

type connWithCancel struct {
	net.Conn
	cancel  context.CancelFunc
	once    sync.Once
	metrics *metrics.Registry
}

func (c *connWithCancel) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.metrics.AddSSHTransportBytes("rx", n)
	}
	return n, err
}

func (c *connWithCancel) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.metrics.AddSSHTransportBytes("tx", n)
	}
	return n, err
}

func (c *connWithCancel) Close() error {
	c.once.Do(c.cancel)
	return c.Conn.Close()
}

// New returns a configured SSH server.
func New(
	cfg Config,
	signer ssh.Signer,
	userCache userLookup,
	sessions *session.Registry,
	logger *slog.Logger,
) *Server {
	aliasSet := make(map[string]struct{}, len(cfg.AllowedAliases))
	for _, alias := range cfg.AllowedAliases {
		normalized := normalizeHost(alias)
		if normalized == "" {
			continue
		}
		aliasSet[normalized] = struct{}{}
	}

	return &Server{
		cfg:       cfg,
		signer:    signer,
		userCache: userCache,
		sessions:  sessions,
		logger:    logger,
		aliases:   aliasSet,
		hostKey:   normalizeHost(cfg.AllowedHost),
		oidcAuth:  cfg.OIDC,
		metrics:   cfg.Metrics,
	}
}

// Start begins accepting SSH connections and blocks until stopped.
func (s *Server) Start() error {
	if s.cfg.Address == "" {
		return errors.New("ssh address must not be empty")
	}
	if s.cfg.AllowedHost == "" || s.cfg.AllowedPort == 0 {
		return errors.New("api server allowlist must be configured")
	}
	if s.signer == nil {
		return errors.New("ssh host key must be configured")
	}

	ln, err := net.Listen("tcp", s.cfg.Address)
	if err != nil {
		return err
	}
	s.ln = ln

	s.logger.Info("gate ssh server started", "address", ln.Addr().String())

	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Temporary() {
				continue
			}
			return err
		}

		go s.handleConn(conn)
	}
}

// Stop stops the SSH server.
func (s *Server) Stop() error {
	if s.ln == nil {
		return nil
	}
	err := s.ln.Close()

	if s.cfg.StopTimeout > 0 {
		_ = s.Drain(s.cfg.StopTimeout)
	}

	return err
}

// Drain waits for active sessions to complete or the timeout to elapse.
// It returns the number of active sessions remaining after the drain window.
func (s *Server) Drain(timeout time.Duration) int {
	if s.sessions == nil || timeout <= 0 {
		return 0
	}

	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for {
		active := countActiveSessions(s.sessions.List())
		if active == 0 {
			return 0
		}
		if time.Now().After(deadline) {
			s.logger.Warn(
				"session drain timeout exceeded",
				"active_sessions", active,
				"timeout", timeout,
			)
			return active
		}
		<-ticker.C
	}
}

func (s *Server) handleConn(conn net.Conn) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	wrappedConn := &connWithCancel{
		Conn:    conn,
		cancel:  cancel,
		metrics: s.metrics,
	}

	if s.cfg.AuthTimeout > 0 {
		_ = wrappedConn.SetDeadline(time.Now().Add(s.cfg.AuthTimeout))
	}

	serverConfig := &ssh.ServerConfig{
		PublicKeyCallback: s.publicKeyCallback(ctx),
	}
	serverConfig.AddHostKey(s.signer)

	serverConn, chans, reqs, err := ssh.NewServerConn(wrappedConn, serverConfig)
	if err != nil {
		_ = wrappedConn.Close()
		return
	}

	_ = wrappedConn.SetDeadline(time.Time{})

	permissions := serverConn.Permissions
	userName := ""
	fingerprint := ""
	if permissions != nil {
		userName = permissions.Extensions["user_name"]
		fingerprint = permissions.Extensions["fingerprint"]
	}

	remoteIP := remoteIP(wrappedConn.RemoteAddr())

	oidcIdentity := sessionOIDCIdentity(permissions)
	sessionRecord, err := s.sessions.Create(
		userName,
		fingerprint,
		remoteIP,
		oidcIdentity,
		serverConn.Close,
	)
	if err != nil {
		_ = serverConn.Close()
		return
	}

	go ssh.DiscardRequests(reqs)

	for newChannel := range chans {
		s.handleChan(newChannel)
	}

	_, _ = s.sessions.Terminate(sessionRecord.ID, "")
}

func (s *Server) handleChan(newChannel ssh.NewChannel) {
	if newChannel.ChannelType() != "direct-tcpip" {
		_ = newChannel.Reject(ssh.UnknownChannelType, "unsupported channel type")
		return
	}

	payload := &directTCPIP{}
	if err := ssh.Unmarshal(newChannel.ExtraData(), payload); err != nil {
		_ = newChannel.Reject(ssh.ConnectionFailed, "invalid channel payload")
		return
	}

	destHost := strings.TrimSpace(payload.DestAddr)
	destPort := int(payload.DestPort)

	resolvedHost, resolvedPort, aliasUsed, ok := s.resolveDestination(destHost, destPort)
	if !ok {
		_ = newChannel.Reject(ssh.Prohibited, "destination not allowed")
		return
	}

	channel, requests, err := newChannel.Accept()
	if err != nil {
		return
	}
	go ssh.DiscardRequests(requests)

	if aliasUsed {
		s.logger.Info(
			"ssh port-forward alias resolved",
			"requested_dest", net.JoinHostPort(destHost, fmt.Sprintf("%d", destPort)),
			"actual_dest", net.JoinHostPort(resolvedHost, fmt.Sprintf("%d", resolvedPort)),
		)
	}

	addr := net.JoinHostPort(resolvedHost, fmt.Sprintf("%d", resolvedPort))
	upstream, err := net.DialTimeout("tcp", addr, s.cfg.DialTimeout)
	if err != nil {
		_ = channel.Close()
		return
	}

	go proxy(channel, upstream)
}

func proxy(client ssh.Channel, upstream net.Conn) {
	defer func() {
		_ = client.Close()
		_ = upstream.Close()
	}()

	go func() {
		_, _ = io.Copy(upstream, client)
		_ = upstream.Close()
	}()

	_, _ = io.Copy(client, upstream)
}

func (s *Server) publicKeyCallback(
	ctx context.Context,
) func(conn ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
	return func(conn ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
		if s.userCache == nil {
			return nil, errors.New("user cache unavailable")
		}

		fingerprint := ssh.FingerprintSHA256(pubKey)
		userName := strings.TrimSpace(conn.User())
		if userName == "" {
			return nil, errors.New("user name required")
		}

		user, ok, err := s.userCache.LookupByUserName(ctx, userName)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, errors.New("permission denied")
		}
		if !fingerprintAllowed(user.PublicKeys, fingerprint) {
			return nil, errors.New("permission denied")
		}

		if !user.SSORequired {
			return basePermissions(user.UserName, fingerprint, nil), nil
		}
		if s.oidcAuth == nil {
			return nil, errors.New("oidc sso required but not configured")
		}
		if len(user.OIDCSubjects) == 0 {
			return nil, errors.New("oidc subjects required")
		}

		return nil, &ssh.PartialSuccessError{
			Next: ssh.ServerAuthCallbacks{
				KeyboardInteractiveCallback: s.oidcKeyboardCallback(ctx, user, fingerprint),
			},
		}
	}
}

func (s *Server) oidcKeyboardCallback(
	ctx context.Context,
	user kube.UserRecord,
	fingerprint string,
) func(conn ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
	return func(_ ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
		if s.oidcAuth == nil {
			return nil, errors.New("oidc sso required but not configured")
		}

		identity, err := s.oidcAuth.Authenticate(
			ctx,
			func(prompt oidc.Prompt) error {
				message := buildOIDCPrompt(prompt)
				_, err := client(
					"Gate SSO",
					"Complete login to continue.",
					[]string{message},
					[]bool{true},
				)
				return err
			},
		)
		if err != nil {
			return nil, err
		}
		if identity.Subject == "" {
			return nil, errors.New("oidc subject missing")
		}
		if !subjectAllowed(user.OIDCSubjects, identity.Subject) {
			return nil, errors.New("permission denied")
		}
		if len(user.OIDCGroups) > 0 && !groupsIntersect(user.OIDCGroups, identity.Groups) {
			return nil, errors.New("permission denied")
		}

		permissions := basePermissions(user.UserName, fingerprint, &identity)
		return permissions, nil
	}
}

func basePermissions(
	userName string,
	fingerprint string,
	identity *oidc.Identity,
) *ssh.Permissions {
	extensions := map[string]string{
		"user_name":   userName,
		"fingerprint": fingerprint,
	}

	if identity != nil {
		if identity.Issuer != "" {
			extensions["oidc_issuer"] = identity.Issuer
		}
		if identity.Subject != "" {
			extensions["oidc_subject"] = identity.Subject
		}
		if len(identity.Groups) > 0 {
			if payload, err := json.Marshal(identity.Groups); err == nil {
				extensions["oidc_groups"] = string(payload)
			}
		}
	}

	return &ssh.Permissions{Extensions: extensions}
}

func sessionOIDCIdentity(perms *ssh.Permissions) *session.OIDCIdentity {
	if perms == nil || len(perms.Extensions) == 0 {
		return nil
	}

	issuer := perms.Extensions["oidc_issuer"]
	subject := perms.Extensions["oidc_subject"]
	groups := decodeOIDCGroups(perms.Extensions["oidc_groups"])
	if issuer == "" && subject == "" && len(groups) == 0 {
		return nil
	}

	return &session.OIDCIdentity{
		Issuer:  issuer,
		Subject: subject,
		Groups:  groups,
	}
}

func decodeOIDCGroups(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}

	var groups []string
	if err := json.Unmarshal([]byte(value), &groups); err != nil {
		return nil
	}

	return groups
}

func buildOIDCPrompt(prompt oidc.Prompt) string {
	if prompt.VerificationURIComplete != "" {
		return fmt.Sprintf(
			"Open %s in your browser to authenticate, then press Enter.",
			prompt.VerificationURIComplete,
		)
	}
	if prompt.UserCode != "" {
		return fmt.Sprintf(
			"Open %s and enter code %s, then press Enter.",
			prompt.VerificationURI,
			prompt.UserCode,
		)
	}

	return fmt.Sprintf(
		"Open %s to authenticate, then press Enter.",
		prompt.VerificationURI,
	)
}

func subjectAllowed(subjects []string, subject string) bool {
	subject = strings.TrimSpace(subject)
	if subject == "" {
		return false
	}

	for _, candidate := range subjects {
		if strings.TrimSpace(candidate) == subject {
			return true
		}
	}

	return false
}

func groupsIntersect(allowed, presented []string) bool {
	if len(allowed) == 0 || len(presented) == 0 {
		return false
	}

	set := make(map[string]struct{}, len(presented))
	for _, value := range presented {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		set[value] = struct{}{}
	}

	for _, candidate := range allowed {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		if _, ok := set[candidate]; ok {
			return true
		}
	}

	return false
}

func (s *Server) resolveDestination(host string, port int) (string, int, bool, bool) {
	if host == "" || port == 0 {
		return "", 0, false, false
	}
	if port != s.cfg.AllowedPort {
		return "", 0, false, false
	}

	normalized := normalizeHost(host)
	if normalized == "" {
		return "", 0, false, false
	}

	if normalized == s.hostKey {
		return s.cfg.AllowedHost, s.cfg.AllowedPort, false, true
	}

	if _, ok := s.aliases[normalized]; ok {
		return s.cfg.AllowedHost, s.cfg.AllowedPort, true, true
	}

	return "", 0, false, false
}

type directTCPIP struct {
	DestAddr   string
	DestPort   uint32
	OriginAddr string
	OriginPort uint32
}

func remoteIP(addr net.Addr) string {
	if addr == nil {
		return ""
	}

	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}

	return host
}

func normalizeHost(host string) string {
	value := strings.TrimSpace(host)
	value = strings.TrimRight(value, ".")
	return strings.ToLower(value)
}

func fingerprintAllowed(publicKeys []string, fingerprint string) bool {
	if fingerprint == "" || len(publicKeys) == 0 {
		return false
	}

	for _, key := range publicKeys {
		pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(strings.TrimSpace(key)))
		if err != nil {
			continue
		}
		if ssh.FingerprintSHA256(pubKey) == fingerprint {
			return true
		}
	}

	return false
}

func countActiveSessions(sessions []session.Session) int {
	active := 0
	for _, record := range sessions {
		if record.State == session.StateActive {
			active++
		}
	}

	return active
}
