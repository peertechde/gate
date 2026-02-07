package session

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"peertech.de/gate/internal/metrics"
)

var ErrMaxSessionsExceeded = errors.New("max concurrent sessions exceeded")

// State represents the lifecycle state of a session.
type State string

const (
	StateActive     State = "active"
	StateTerminated State = "terminated"
)

// TerminationReason provides a reason for session termination.
type TerminationReason string

const (
	TerminationReasonRevoked         TerminationReason = "revoked"
	TerminationReasonAdminTerminated TerminationReason = "admin_terminated"
	TerminationReasonMaxDuration     TerminationReason = "max_duration"
	TerminationReasonError           TerminationReason = "error"
)

// Session describes an SSH session.
type Session struct {
	ID                   string
	UserName             string
	PublicKeyFingerprint string
	OIDCIssuer           string
	OIDCSubject          string
	OIDCGroups           []string
	SourceIP             string
	StartTime            time.Time
	EndTime              time.Time
	State                State
	TerminationReason    TerminationReason
}

// OIDCIdentity captures the optional OIDC identity bound to a session.
type OIDCIdentity struct {
	Issuer  string
	Subject string
	Groups  []string
}

type entry struct {
	session Session
	closeFn func() error
}

// Registry tracks active sessions.
type Registry struct {
	mu          sync.RWMutex
	sessions    map[string]*entry
	maxSessions int
	metrics     *metrics.Registry
}

func NewRegistry(maxSessions int, metricsRegistry *metrics.Registry) *Registry {
	return &Registry{
		sessions:    make(map[string]*entry),
		maxSessions: maxSessions,
		metrics:     metricsRegistry,
	}
}

// Create registers a new session.
func (r *Registry) Create(
	userName, fingerprint, sourceIP string,
	oidcIdentity *OIDCIdentity,
	closeFn func() error,
) (Session, error) {
	if userName == "" || fingerprint == "" {
		return Session{}, fmt.Errorf("user name and fingerprint are required")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.maxSessions > 0 && len(r.sessions) >= r.maxSessions {
		return Session{}, ErrMaxSessionsExceeded
	}

	sessionID, err := newSessionID()
	if err != nil {
		return Session{}, err
	}

	record := Session{
		ID:                   sessionID,
		UserName:             userName,
		PublicKeyFingerprint: fingerprint,
		SourceIP:             sourceIP,
		StartTime:            time.Now().UTC(),
		State:                StateActive,
	}
	if oidcIdentity != nil {
		record.OIDCIssuer = oidcIdentity.Issuer
		record.OIDCSubject = oidcIdentity.Subject
		record.OIDCGroups = append([]string(nil), oidcIdentity.Groups...)
	}
	item := &entry{
		session: record,
		closeFn: closeFn,
	}

	r.sessions[sessionID] = item
	r.updateActiveGaugeLocked()

	return item.session, nil
}

// Get returns a session by ID.
func (r *Registry) Get(id string) (Session, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	item, ok := r.sessions[id]
	if !ok {
		return Session{}, false
	}

	return item.session, true
}

// List returns a snapshot of all sessions.
func (r *Registry) List() []Session {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]Session, 0, len(r.sessions))
	for _, item := range r.sessions {
		result = append(result, item.session)
	}

	return result
}

// Terminate marks a session as terminated and closes the underlying connection.
func (r *Registry) Terminate(id string, reason TerminationReason) (Session, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	item, ok := r.sessions[id]
	if !ok {
		return Session{}, false
	}

	if item.session.State == StateTerminated {
		return item.session, true
	}

	if item.closeFn != nil {
		_ = item.closeFn()
		item.closeFn = nil
	}

	item.session.State = StateTerminated
	item.session.TerminationReason = reason
	item.session.EndTime = time.Now().UTC()

	r.observeTerminationLocked(reason)
	r.updateActiveGaugeLocked()
	return item.session, true
}

// TerminateByUser marks all sessions for a user as terminated.
func (r *Registry) TerminateByUser(userName string, reason TerminationReason) int {
	userName = strings.TrimSpace(userName)
	if userName == "" {
		return 0
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now().UTC()
	terminated := 0
	for _, item := range r.sessions {
		if item.session.UserName != userName || item.session.State == StateTerminated {
			continue
		}

		if item.closeFn != nil {
			_ = item.closeFn()
			item.closeFn = nil
		}

		item.session.State = StateTerminated
		item.session.TerminationReason = reason
		item.session.EndTime = now
		r.observeTerminationLocked(reason)
		terminated++
	}

	if terminated > 0 {
		r.updateActiveGaugeLocked()
	}

	return terminated
}

// TerminateAll marks all active sessions as terminated.
func (r *Registry) TerminateAll(reason TerminationReason) int {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now().UTC()
	terminated := 0
	for _, item := range r.sessions {
		if item.session.State == StateTerminated {
			continue
		}

		if item.closeFn != nil {
			_ = item.closeFn()
			item.closeFn = nil
		}

		item.session.State = StateTerminated
		item.session.TerminationReason = reason
		item.session.EndTime = now
		r.observeTerminationLocked(reason)
		terminated++
	}

	if terminated > 0 {
		r.updateActiveGaugeLocked()
	}

	return terminated
}

// Count returns the number of tracked sessions.
func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.sessions)
}

func (r *Registry) updateActiveGaugeLocked() {
	if r.metrics == nil {
		return
	}

	active := 0
	for _, item := range r.sessions {
		if item.session.State == StateActive {
			active++
		}
	}
	r.metrics.SetActiveSessions(active)
}

func (r *Registry) observeTerminationLocked(reason TerminationReason) {
	if r.metrics == nil || reason == "" {
		return
	}
	r.metrics.ObserveSessionTermination(string(reason))
}

func newSessionID() (string, error) {
	id, err := uuid.NewRandom()
	if err != nil {
		return "", fmt.Errorf("generate session id: %w", err)
	}

	return id.String(), nil
}
