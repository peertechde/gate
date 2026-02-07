package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/sync/errgroup"

	"peertech.de/gate/internal/config"
	"peertech.de/gate/internal/health"
	"peertech.de/gate/internal/httpserver"
	"peertech.de/gate/internal/kube"
	"peertech.de/gate/internal/logging"
	"peertech.de/gate/internal/metrics"
	"peertech.de/gate/internal/oidc"
	"peertech.de/gate/internal/session"
	"peertech.de/gate/internal/sshserver"
)

type App struct {
	logger          *slog.Logger
	readiness       *health.Readiness
	sessionRegistry *session.Registry
	userCache       *kube.UserCache
	sshSrv          *sshserver.Server
	httpServer      *httpserver.Server
	lifecycle       *session.Lifecycle
}

func main() {
	app, err := Setup()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	if err := app.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func Setup() (*App, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	logger, err := logging.New(cfg.Logging.Level)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize logger: %w", err)
	}

	readiness := health.NewReadiness(false)

	var metricsRegistry *metrics.Registry
	if cfg.Metrics.Enabled {
		metricsRegistry = metrics.New()
	}

	sessionRegistry := session.NewRegistry(cfg.Limits.MaxConcurrentSessions, metricsRegistry)

	clients, err := kube.NewClients(
		kube.RestConfigOptions{
			Kubeconfig: cfg.Kube.Kubeconfig,
			QPS:        cfg.Kube.QPS,
			Burst:      cfg.Kube.Burst,
			Timeout:    cfg.Kube.Timeout,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize kube clients: %w", err)
	}

	hostKeyLoader := kube.NewHostKeyLoader(
		clients.Clientset,
		kube.HostKeyOptions{
			SecretName:      cfg.HostKey.SecretName,
			SecretNamespace: cfg.HostKey.SecretNamespace,
			SecretKey:       cfg.HostKey.SecretKey,
			Bootstrap:       cfg.HostKey.Bootstrap,
			Timeout:         cfg.Kube.Timeout,
		},
		logger,
	)
	signer, err := hostKeyLoader.Load(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to load host key: %w", err)
	}

	userCache, err := kube.NewUserCache(
		clients.Dynamic,
		cfg.Kube.UserNamespace,
		cfg.Kube.CacheResyncPeriod,
		logger,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create user cache: %w", err)
	}

	userCache.SetRevokeHandler(
		func(record kube.UserRecord) {
			terminated := sessionRegistry.TerminateByUser(
				record.UserName,
				session.TerminationReasonRevoked,
			)
			if terminated == 0 {
				return
			}
			logger.Warn(
				"sessions terminated due to user revocation",
				"user_name", record.UserName,
				"terminated", terminated,
				"resource_version", record.ResourceVersion,
			)
		},
	)

	if err := userCache.Start(context.Background(), cfg.Kube.CacheSyncTimeout); err != nil {
		return nil, fmt.Errorf("failed to start user cache: %w", err)
	}

	var oidcAuth *oidc.Authenticator
	if cfg.OIDC.Enabled() {
		oidcAuth, err = oidc.NewAuthenticator(
			context.Background(),
			oidc.Config{
				IssuerURL:     cfg.OIDC.IssuerURL,
				ClientID:      cfg.OIDC.ClientID,
				ClientSecret:  cfg.OIDC.ClientSecret,
				Scopes:        cfg.OIDC.Scopes,
				GroupClaim:    cfg.OIDC.GroupClaim,
				DeviceTimeout: cfg.OIDC.DeviceTimeout,
				HTTPTimeout:   cfg.OIDC.HTTPTimeout,
			},
		)
		if err != nil {
			userCache.Stop()
			return nil, fmt.Errorf("failed to initialize oidc authenticator: %w", err)
		}
	}

	sshCfg := sshserver.Config{
		Address:        cfg.SSH.Address,
		AuthTimeout:    cfg.SSH.AuthTimeout,
		DialTimeout:    cfg.SSH.DialTimeout,
		StopTimeout:    cfg.SSH.StopTimeout,
		AllowedHost:    cfg.APIServer.Host,
		AllowedPort:    cfg.APIServer.Port,
		AllowedAliases: cfg.APIServer.AllowedAliases,
		OIDC:           oidcAuth,
	}

	return &App{
		logger:          logger,
		readiness:       readiness,
		sessionRegistry: sessionRegistry,
		userCache:       userCache,
		sshSrv: sshserver.New(
			sshCfg,
			signer,
			userCache,
			sessionRegistry,
			logger,
		),
		httpServer: httpserver.New(
			cfg.HTTP,
			logger,
			readiness,
			metricsRegistry,
			sessionRegistry,
		),
		lifecycle: session.NewLifecycle(
			sessionRegistry,
			cfg.Limits.MaxSessionDuration,
			logger,
		),
	}, nil
}

func (a *App) Run() error {
	defer a.userCache.Stop()

	a.readiness.SetReady(true)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	g, groupCtx := errgroup.WithContext(ctx)
	g.Go(func() error {
		err := a.httpServer.Start()
		if err == nil || err == http.ErrServerClosed {
			return nil
		}
		return err
	})
	g.Go(func() error {
		err := a.sshSrv.Start()
		if err == nil || errors.Is(err, net.ErrClosed) {
			return nil
		}
		return err
	})
	g.Go(func() error {
		a.lifecycle.Run(groupCtx)
		return nil
	})

	// Wait for signal or error from any goroutine.
	<-groupCtx.Done()

	a.readiness.SetReady(false)

	if err := a.sshSrv.Stop(); err != nil {
		a.logger.Error("ssh server shutdown error", "error", err)
	}

	terminated := a.sessionRegistry.TerminateAll(session.TerminationReasonError)
	if terminated > 0 {
		a.logger.Info(
			"terminated active sessions on shutdown",
			"terminated", terminated,
		)
	}

	if err := a.httpServer.Stop(); err != nil {
		a.logger.Error("http server shutdown error", "error", err)
	}

	if err := g.Wait(); err != nil {
		return fmt.Errorf("service stopped with error: %w", err)
	}

	a.logger.Info("shutdown complete")
	return nil
}
