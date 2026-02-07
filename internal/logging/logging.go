package logging

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
)

func New(level string) (*slog.Logger, error) {
	return NewWithWriter(level, os.Stdout)
}

func NewWithWriter(level string, out io.Writer) (*slog.Logger, error) {
	lvl, err := parseLevel(level)
	if err != nil {
		return nil, err
	}

	handler := slog.NewTextHandler(
		out,
		&slog.HandlerOptions{
			Level: lvl,
		},
	)

	return slog.New(handler), nil
}

// NewTestLogger returns a logger that discards output to keep tests quiet.
func NewTestLogger() *slog.Logger {
	handler := slog.NewTextHandler(
		io.Discard,
		&slog.HandlerOptions{
			Level: slog.LevelDebug,
		},
	)

	return slog.New(handler)
}

func parseLevel(level string) (slog.Level, error) {
	switch strings.ToLower(level) {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, fmt.Errorf("unsupported log level: %s", level)
	}
}
