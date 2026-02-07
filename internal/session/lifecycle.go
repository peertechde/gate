package session

import (
	"context"
	"log/slog"
	"time"
)

const (
	minSweepInterval = time.Second
	maxSweepInterval = time.Minute
)

// Lifecycle enforces session lifecycle constraints.
type Lifecycle struct {
	registry      *Registry
	maxDuration   time.Duration
	sweepInterval time.Duration
	logger        *slog.Logger
	now           func() time.Time
}

func NewLifecycle(registry *Registry, maxDuration time.Duration, logger *slog.Logger) *Lifecycle {
	interval := sweepInterval(maxDuration)
	return &Lifecycle{
		registry:      registry,
		maxDuration:   maxDuration,
		sweepInterval: interval,
		logger:        logger,
		now:           time.Now,
	}
}

// Run starts the lifecycle sweeper and blocks until the context is done.
func (l *Lifecycle) Run(ctx context.Context) {
	if l.registry == nil || l.maxDuration <= 0 {
		return
	}

	ticker := time.NewTicker(l.sweepInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = l.Sweep()
		}
	}
}

// Sweep enforces max duration once and returns the number of terminated sessions.
func (l *Lifecycle) Sweep() int {
	if l.registry == nil || l.maxDuration <= 0 {
		return 0
	}

	now := l.now().UTC()
	terminated := 0
	for _, record := range l.registry.List() {
		if record.State != StateActive {
			continue
		}
		if now.Sub(record.StartTime) < l.maxDuration {
			continue
		}

		_, ok := l.registry.Terminate(record.ID, TerminationReasonMaxDuration)
		if ok {
			terminated++
			l.logger.Info(
				"session terminated due to max duration",
				"session_id", record.ID,
				"user_name", record.UserName,
				"max_duration", l.maxDuration,
			)
		}
	}

	return terminated
}

func sweepInterval(maxDuration time.Duration) time.Duration {
	if maxDuration <= 0 {
		return maxSweepInterval
	}

	interval := maxDuration / 4
	if interval < minSweepInterval {
		return minSweepInterval
	}
	if interval > maxSweepInterval {
		return maxSweepInterval
	}
	return interval
}
