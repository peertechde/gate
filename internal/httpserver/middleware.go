package httpserver

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"peertech.de/gate/internal/metrics"
	"peertech.de/gate/internal/requestid"
)

type ctxKey string

const (
	requestIDKey ctxKey = "request_id"
)

func chain(handler http.Handler, middleware ...func(http.Handler) http.Handler) http.Handler {
	for i := len(middleware) - 1; i >= 0; i-- {
		handler = middleware[i](handler)
	}

	return handler
}

func requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := requestid.Ensure(w, r)
		ctx := context.WithValue(r.Context(), requestIDKey, requestID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func timeoutMiddleware(timeout time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if timeout <= 0 {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), timeout)
			defer cancel()
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func observabilityMiddleware(
	logger *slog.Logger,
	registry *metrics.Registry,
) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			recorder := &responseRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(recorder, r)
			duration := time.Since(start)

			requestID := RequestIDFromContext(r.Context())
			path := r.URL.Path
			method := r.Method

			if registry != nil {
				registry.ObserveRequest(path, method, recorder.status, duration)
			}

			logLevel := slog.LevelInfo
			if recorder.status >= http.StatusInternalServerError {
				logLevel = slog.LevelError
			} else if recorder.status >= http.StatusBadRequest {
				logLevel = slog.LevelWarn
			}

			logger.Log(
				r.Context(),
				logLevel,
				"http request",
				"request_id", requestID,
				"method", method,
				"path", path,
				"status", recorder.status,
				"duration_ms", duration.Milliseconds(),
			)
		})
	}
}

// RequestIDFromContext returns the request ID stored in the context, if any.
func RequestIDFromContext(ctx context.Context) string {
	value, ok := ctx.Value(requestIDKey).(string)
	if !ok {
		return ""
	}

	return value
}

type responseRecorder struct {
	http.ResponseWriter
	status int
}

func (r *responseRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}
