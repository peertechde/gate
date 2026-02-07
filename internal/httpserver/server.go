package httpserver

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"

	"github.com/go-chi/chi/v5"

	"peertech.de/gate/internal/config"
	"peertech.de/gate/internal/controlapi"
	"peertech.de/gate/internal/health"
	"peertech.de/gate/internal/metrics"
	"peertech.de/gate/internal/session"
)

// Server wraps the Gate HTTP server lifecycle.
type Server struct {
	cfg        config.HTTPConfig
	httpServer *http.Server
	ln         net.Listener
	readiness  *health.Readiness
	logger     *slog.Logger
}

func New(
	cfg config.HTTPConfig,
	logger *slog.Logger,
	readiness *health.Readiness,
	registry *metrics.Registry,
	sessions *session.Registry,
) *Server {
	router := chi.NewRouter()
	router.Use(
		requestIDMiddleware,
		timeoutMiddleware(cfg.RequestTimeout),
		observabilityMiddleware(logger, registry),
	)

	router.Get("/livez", health.LivenessHandler().ServeHTTP)
	router.Get("/readyz", health.ReadinessHandler(readiness).ServeHTTP)
	router.Get("/healthz", health.HealthHandler(readiness).ServeHTTP)

	if registry != nil {
		router.Handle("/metrics", registry.Handler())
	} else {
		router.Handle("/metrics", http.NotFoundHandler())
	}
	if sessions != nil {
		controlapi.New(sessions, logger).Register(router)
	}

	httpServer := &http.Server{
		Addr:              cfg.Address,
		Handler:           router,
		ReadTimeout:       cfg.ReadTimeout,
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
	}

	return &Server{
		cfg:        cfg,
		httpServer: httpServer,
		readiness:  readiness,
		logger:     logger,
	}
}

// Start begins serving HTTP requests and blocks until stopped.
func (s *Server) Start() error {
	if s.httpServer == nil {
		return errors.New("http server is not initialized")
	}

	ln, err := net.Listen("tcp", s.httpServer.Addr)
	if err != nil {
		return err
	}

	s.ln = ln
	s.logger.Info("gate http server started", "address", ln.Addr().String())

	return s.httpServer.Serve(ln)
}

// Stop gracefully shuts down the HTTP server.
func (s *Server) Stop() error {
	if s.httpServer == nil {
		return nil
	}

	stopCtx, cancel := context.WithTimeout(context.Background(), s.cfg.StopTimeout)
	defer cancel()

	return s.httpServer.Shutdown(stopCtx)
}
