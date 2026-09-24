// Package telemetry configures logging, tracing and metrics.
package telemetry

import (
	"log/slog"
	"os"
	"strings"
)

// NewLogger builds the process logger. Secrets are never logged by
// construction: callers pass identifiers, not credentials.
func NewLogger(level, format, version string) *slog.Logger {
	var lvl slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn", "warning":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: lvl}
	var h slog.Handler
	if format == "text" {
		h = slog.NewTextHandler(os.Stderr, opts)
	} else {
		h = slog.NewJSONHandler(os.Stderr, opts)
	}
	l := slog.New(h).With("service", "supermcp", "version", version)
	slog.SetDefault(l)
	return l
}
