package controlapi

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"peertech.de/gate/internal/session"
)

const (
	defaultLimit = 50
	maxLimit     = 200
)

const (
	sessionsPath = "/api/v1/sessions"
)

// Handler provides the control API endpoints.
type Handler struct {
	sessions *session.Registry
	logger   *slog.Logger
}

func New(sessions *session.Registry, logger *slog.Logger) *Handler {
	return &Handler{
		sessions: sessions,
		logger:   logger,
	}
}

// Register wires control API routes into the provided router.
func (h *Handler) Register(router chi.Router) {
	router.Get(sessionsPath, h.handleSessions)
	router.Get(sessionsPath+"/{session_id}", h.getSession)
	router.Post(sessionsPath+"/{session_id}:terminate", h.terminateSession)
}

func (h *Handler) handleSessions(w http.ResponseWriter, r *http.Request) {
	if h.sessions == nil {
		writeError(w, r, apiError{
			status:  http.StatusInternalServerError,
			code:    Internal,
			message: "session registry unavailable",
		})
		return
	}

	limit, offset, orderBy, err := parseListParams(r)
	if err != nil {
		writeError(w, r, *err)
		return
	}

	sessions := filterActiveSessions(h.sessions.List())
	sortSessions(sessions, orderBy)

	if offset > len(sessions) {
		offset = len(sessions)
	}
	end := offset + limit
	if end > len(sessions) {
		end = len(sessions)
	}

	page := sessions[offset:end]
	resp := SessionListResponse{Sessions: make([]Session, len(page))}
	for i, s := range page {
		resp.Sessions[i] = toSessionModel(s)
	}

	writeJSON(w, r, http.StatusOK, resp)
}

func (h *Handler) getSession(w http.ResponseWriter, r *http.Request) {
	if h.sessions == nil {
		writeError(w, r, apiError{
			status:  http.StatusInternalServerError,
			code:    Internal,
			message: "session registry unavailable",
		})
		return
	}

	sessionID := strings.TrimSpace(chi.URLParam(r, "session_id"))
	if sessionID == "" {
		writeError(w, r, apiError{
			status:  http.StatusBadRequest,
			code:    InvalidArgument,
			message: "session_id is required",
			details: map[string]any{"field": "session_id"},
		})
		return
	}

	record, ok := h.sessions.Get(sessionID)
	if !ok {
		writeError(w, r, apiError{
			status:  http.StatusNotFound,
			code:    NotFound,
			message: "session not found",
			details: map[string]any{"session_id": sessionID},
		})
		return
	}

	writeJSON(w, r, http.StatusOK, toSessionModel(record))
}

func (h *Handler) terminateSession(w http.ResponseWriter, r *http.Request) {
	if h.sessions == nil {
		writeError(w, r, apiError{
			status:  http.StatusInternalServerError,
			code:    Internal,
			message: "session registry unavailable",
		})
		return
	}

	sessionID := strings.TrimSpace(chi.URLParam(r, "session_id"))
	if sessionID == "" {
		writeError(w, r, apiError{
			status:  http.StatusBadRequest,
			code:    InvalidArgument,
			message: "session_id is required",
			details: map[string]any{"field": "session_id"},
		})
		return
	}

	record, ok := h.sessions.Terminate(sessionID, session.TerminationReasonAdminTerminated)
	if !ok {
		writeError(w, r, apiError{
			status:  http.StatusNotFound,
			code:    NotFound,
			message: "session not found",
			details: map[string]any{"session_id": sessionID},
		})
		return
	}

	requestID := ensureRequestID(w, r)
	h.logger.Info(
		"session termination requested",
		"request_id", requestID,
		"session_id", sessionID,
		"user_name", record.UserName,
		"state", record.State,
		"termination_reason", record.TerminationReason,
	)

	writeJSON(w, r, http.StatusOK, toSessionModel(record))
}

func writeJSON(w http.ResponseWriter, r *http.Request, status int, payload any) {
	ensureRequestID(w, r)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(payload)
}

func parseListParams(r *http.Request) (int, int, ListSessionsParamsOrderBy, *apiError) {
	query := r.URL.Query()

	limit := defaultLimit
	if raw := strings.TrimSpace(query.Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > maxLimit {
			return 0, 0, "", &apiError{
				status:  http.StatusBadRequest,
				code:    InvalidArgument,
				message: "limit must be between 1 and 200",
				details: map[string]any{"field": "limit"},
			}
		}
		limit = parsed
	}

	offset := 0
	if raw := strings.TrimSpace(query.Get("offset")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 0 {
			return 0, 0, "", &apiError{
				status:  http.StatusBadRequest,
				code:    InvalidArgument,
				message: "offset must be >= 0",
				details: map[string]any{"field": "offset"},
			}
		}
		offset = parsed
	}

	orderBy := ListSessionsParamsOrderByStartTimeDesc
	if raw := strings.TrimSpace(query.Get("order_by")); raw != "" {
		if raw != string(ListSessionsParamsOrderByStartTimeDesc) &&
			raw != string(ListSessionsParamsOrderByStartTimeAsc) {
			return 0, 0, "", &apiError{
				status:  http.StatusBadRequest,
				code:    InvalidArgument,
				message: "order_by must be start_time asc or start_time desc",
				details: map[string]any{"field": "order_by"},
			}
		}
		orderBy = ListSessionsParamsOrderBy(raw)
	}

	return limit, offset, orderBy, nil
}

func filterActiveSessions(sessions []session.Session) []session.Session {
	active := make([]session.Session, 0, len(sessions))
	for _, record := range sessions {
		if record.State == session.StateActive {
			active = append(active, record)
		}
	}
	return active
}

func sortSessions(sessions []session.Session, orderBy ListSessionsParamsOrderBy) {
	if orderBy == ListSessionsParamsOrderByStartTimeAsc {
		sort.Slice(sessions, func(i, j int) bool {
			return sessions[i].StartTime.Before(sessions[j].StartTime)
		})
		return
	}

	sort.Slice(sessions, func(i, j int) bool {
		return sessions[i].StartTime.After(sessions[j].StartTime)
	})
}
