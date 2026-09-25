// Package config loads the process configuration from the environment and
// validates it before anything else starts.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/supermcpco/supermcp/internal/hardening"
)

// Config is the validated process configuration.
type Config struct {
	// Listen is the main HTTP listener (API, MCP, UI).
	Listen string
	// AdminListen serves /metrics and pprof (dev only). Empty disables it.
	AdminListen string
	// PublicURL is the externally visible base URL; it is the OAuth issuer
	// and the base for MCP resource identifiers.
	PublicURL *url.URL

	DatabaseURL      string
	MaintDatabaseURL string // maintenance role (BYPASSRLS); defaults to DatabaseURL
	RedisURL         string

	LogLevel  string
	LogFormat string // json | text

	Dev              bool
	MigrateOnStart   bool
	OpenRegistration bool
	DCRMode          string
	MCPJSONResponse  bool
	SQLiteRoot       string
	ShutdownTimeout  time.Duration
	// AuthFreshWindow is how recently a browser session must have signed
	// in, or re-authenticated, to create credentials, change who may do
	// what, or change the security settings. See httpapi.requireFresh.
	AuthFreshWindow time.Duration

	RateLimit RateLimit
	Metrics   Metrics
	Tracing   Tracing

	Version string
}

// RateLimit is what the limiter needs: the per-route budgets, and the two
// numbers that decide how close it stays to them when Redis is gone.
type RateLimit struct {
	// Enabled is on unless an operator turns it off.
	Enabled bool
	Budgets hardening.Budgets
	// MaxKeys bounds the in-memory bucket map, so a distributed flood
	// cannot turn the limiter into the outage.
	MaxKeys int
	// ExpectedReplicas is how many replicas share one intended ceiling.
	// The in-memory backing divides every budget by it.
	ExpectedReplicas int
}

// Tracing is where spans go, and how many of them.
type Tracing struct {
	// Endpoint is an OTLP/HTTP collector. Empty is off, which is the
	// default: an instance with no collector should not be trying to
	// reach one.
	Endpoint string
	// Sample is the fraction of traces kept, between 0 and 1.
	Sample float64
}

// Metrics is what the exposition publishes.
type Metrics struct {
	// PerTool turns on the per-tool series. Off by default: tool names are
	// operator data and nothing caps how many an organisation installs.
	PerTool bool
	// PerToolCap is how many distinct tool names get their own series
	// before the rest collapse into one.
	PerToolCap int
}

// DefaultAuthFreshWindow is the freshness window when
// SUPERMCP_AUTH_FRESH_WINDOW is not set.
const DefaultAuthFreshWindow = 5 * time.Minute

// Load reads the environment. Every variable is prefixed SUPERMCP_ except
// the conventional DATABASE_URL and REDIS_URL, which are accepted both
// ways.
func Load(version string) (*Config, error) { return load(version, true) }

// LoadOffline is for the commands that never serve a request:
// `audit verify`, `keys verify`, `keys rotate-kek` and the import. They
// need the database and the master key; the address clients reach has
// nothing to do with them, and requiring it turns a scheduled chain check
// into a command that fails on a setting nobody had to set.
func LoadOffline(version string) (*Config, error) { return load(version, false) }

func load(version string, serving bool) (*Config, error) {
	c := &Config{
		Listen:           getenv("SUPERMCP_LISTEN", ":8080"),
		AdminListen:      getenv("SUPERMCP_ADMIN_LISTEN", ""),
		DatabaseURL:      first(os.Getenv("SUPERMCP_DATABASE_URL"), os.Getenv("DATABASE_URL")),
		MaintDatabaseURL: os.Getenv("SUPERMCP_MAINT_DATABASE_URL"),
		RedisURL:         first(os.Getenv("SUPERMCP_REDIS_URL"), os.Getenv("REDIS_URL")),
		LogLevel:         getenv("SUPERMCP_LOG_LEVEL", "info"),
		LogFormat:        getenv("SUPERMCP_LOG_FORMAT", "json"),
		Dev:              boolenv("SUPERMCP_DEV"),
		OpenRegistration: boolenv("SUPERMCP_OPEN_REGISTRATION"),
		DCRMode:          getenv("SUPERMCP_DCR_MODE", "approval"),
		MCPJSONResponse:  getenv("SUPERMCP_MCP_RESPONSE_MODE", "sse") == "json",
		SQLiteRoot:       os.Getenv("SUPERMCP_SQLITE_ROOT"),
		MigrateOnStart:   boolenv("SUPERMCP_MIGRATE_ON_START"),
		ShutdownTimeout:  durenv("SUPERMCP_SHUTDOWN_TIMEOUT", 20*time.Second),
		AuthFreshWindow:  DefaultAuthFreshWindow,
		Version:          version,
	}
	if c.MaintDatabaseURL == "" {
		c.MaintDatabaseURL = c.DatabaseURL
	}

	budgets, err := budgetsFromEnv()

	var errs []error
	if err != nil {
		errs = append(errs, err)
	}
	c.RateLimit = RateLimit{
		Enabled:          enabled("SUPERMCP_RATELIMIT_ENABLED"),
		Budgets:          budgets,
		MaxKeys:          intenv("SUPERMCP_RATELIMIT_MAX_KEYS", 100_000),
		ExpectedReplicas: intenv("SUPERMCP_EXPECTED_REPLICAS", 1),
	}
	c.Metrics = Metrics{
		PerTool:    boolenv("SUPERMCP_METRICS_PER_TOOL"),
		PerToolCap: intenv("SUPERMCP_METRICS_PER_TOOL_CAP", 5000),
	}
	c.Tracing = Tracing{
		// OTEL_EXPORTER_OTLP_ENDPOINT is what every other tool in a
		// cluster reads, so it is accepted too rather than made a special
		// case of this one.
		Endpoint: first(getenv("SUPERMCP_OTLP_ENDPOINT", ""), os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")),
		Sample:   floatenv("SUPERMCP_TRACE_SAMPLE", 0.01),
	}
	if v := os.Getenv("SUPERMCP_AUTH_FRESH_WINDOW"); v != "" {
		// Refused rather than defaulted: a typo that quietly turned this
		// into five minutes would be harmless, but one that turned it into
		// a year would switch the check off without anyone noticing.
		d, err := time.ParseDuration(v)
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("SUPERMCP_AUTH_FRESH_WINDOW %q is not a duration, for example 5m", v))
		case d < time.Minute || d > 24*time.Hour:
			errs = append(errs, fmt.Errorf("SUPERMCP_AUTH_FRESH_WINDOW must be between 1m and 24h, got %s", d))
		default:
			c.AuthFreshWindow = d
		}
	}
	if c.Tracing.Sample < 0 || c.Tracing.Sample > 1 {
		errs = append(errs, fmt.Errorf("SUPERMCP_TRACE_SAMPLE must be between 0 and 1, got %v", c.Tracing.Sample))
	}

	pub := getenv("SUPERMCP_PUBLIC_URL", "")
	if pub == "" {
		if c.Dev || !serving {
			pub = "http://localhost:8080"
		} else {
			errs = append(errs, errors.New("SUPERMCP_PUBLIC_URL is required (the externally visible https URL)"))
		}
	}
	if pub != "" {
		u, err := url.Parse(pub)
		switch {
		case err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https"):
			errs = append(errs, fmt.Errorf("SUPERMCP_PUBLIC_URL %q is not an absolute http(s) URL", pub))
		case u.Scheme == "http" && !isLoopback(u.Hostname()) && !c.Dev:
			errs = append(errs, fmt.Errorf("SUPERMCP_PUBLIC_URL must use https unless it points at loopback (got %q)", pub))
		default:
			u.Path = strings.TrimRight(u.Path, "/")
			c.PublicURL = u
		}
	}
	if c.DatabaseURL == "" {
		errs = append(errs, errors.New("DATABASE_URL is required"))
	}
	switch c.LogFormat {
	case "json", "text":
	default:
		errs = append(errs, fmt.Errorf("SUPERMCP_LOG_FORMAT must be json or text, got %q", c.LogFormat))
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return c, nil
}

// budgetsFromEnv reads the six route budgets, each written "N/duration".
// Every one of them is reported, so an operator who mistyped two finds out
// about both in the same boot.
func budgetsFromEnv() (hardening.Budgets, error) {
	b := hardening.DefaultBudgets()
	var errs []error
	for _, s := range []struct {
		key   string
		def   string
		limit *hardening.Limit
	}{
		{"SUPERMCP_RATELIMIT_SIGNIN", "10/1m", &b.SignIn},
		{"SUPERMCP_RATELIMIT_REGISTER", "5/1h", &b.Register},
		{"SUPERMCP_RATELIMIT_INVITE", "5/1h", &b.Invite},
		{"SUPERMCP_RATELIMIT_DCR", "10/1h", &b.DCR},
		{"SUPERMCP_RATELIMIT_TOOL_CALL", "600/1m", &b.ToolCall},
		{"SUPERMCP_RATELIMIT_API", "300/1m", &b.API},
	} {
		burst, window, err := parseBudget(getenv(s.key, s.def))
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", s.key, err))
			continue
		}
		s.limit.Burst, s.limit.Window = burst, window
	}
	return b, errors.Join(errs...)
}

// parseBudget reads "N/duration", for example "10/1m".
//
// A malformed budget fails the boot rather than falling back to the
// default, because a limit nobody notices is off is worse than no limit:
// the dashboard says the route is protected and it is not.
func parseBudget(v string) (int, time.Duration, error) {
	count, window, ok := strings.Cut(v, "/")
	if !ok {
		return 0, 0, fmt.Errorf("budget %q must be written requests/duration, for example 10/1m", v)
	}
	n, err := strconv.Atoi(strings.TrimSpace(count))
	if err != nil || n <= 0 {
		return 0, 0, fmt.Errorf("budget %q needs a positive request count before the slash", v)
	}
	d, err := time.ParseDuration(strings.TrimSpace(window))
	if err != nil || d <= 0 {
		return 0, 0, fmt.Errorf("budget %q needs a positive duration after the slash, for example 1m or 1h", v)
	}
	return n, d, nil
}

func isLoopback(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1" || strings.HasSuffix(host, ".localhost")
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func first(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func boolenv(k string) bool {
	v, _ := strconv.ParseBool(os.Getenv(k))
	return v
}

// enabled reads a switch that is on unless it is explicitly turned off. A
// value that does not parse leaves the defence on, which is the safe way
// to read a typo.
func enabled(k string) bool {
	v := os.Getenv(k)
	if v == "" {
		return true
	}
	b, err := strconv.ParseBool(v)
	return err != nil || b
}

// floatenv reads a fraction. A value that is not a number is the
// default rather than an error, because the range check below is what a
// reader needs to see, not a parse failure.
func floatenv(k string, def float64) float64 {
	if v := os.Getenv(k); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return def
}

func intenv(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

func durenv(k string, def time.Duration) time.Duration {
	if v := os.Getenv(k); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}
