package config

import (
	"strings"
	"testing"
	"time"
)

// TestAuthFreshWindow cannot run in parallel: it sets the environment.
func TestAuthFreshWindow(t *testing.T) {
	cases := []struct {
		value   string
		want    time.Duration
		wantErr string
	}{
		{"", DefaultAuthFreshWindow, ""},
		{"15m", 15 * time.Minute, ""},
		{"1m", time.Minute, ""},
		{"30s", 0, "between 1m and 24h"},
		{"48h", 0, "between 1m and 24h"},
		{"five minutes", 0, "is not a duration"},
	}
	for _, c := range cases {
		t.Run(c.value, func(t *testing.T) {
			t.Setenv("DATABASE_URL", "postgres://example.invalid/db")
			t.Setenv("SUPERMCP_PUBLIC_URL", "https://supermcp.example")
			t.Setenv("SUPERMCP_AUTH_FRESH_WINDOW", c.value)
			cfg, err := Load("test")
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("err = %v, want one saying %q", err, c.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cfg.AuthFreshWindow != c.want {
				t.Errorf("window = %s, want %s", cfg.AuthFreshWindow, c.want)
			}
		})
	}
}

// TestMCPSessionBounds cannot run in parallel: it sets the environment.
func TestMCPSessionBounds(t *testing.T) {
	cases := []struct {
		name, max, idle string
		wantMax         int
		wantIdle        time.Duration
		wantErr         string
	}{
		{"defaults", "", "", DefaultMCPMaxSessions, DefaultMCPSessionIdle, ""},
		{"set", "200", "5m", 200, 5 * time.Minute, ""},
		{"no sessions", "0", "", 0, 0, "SUPERMCP_MCP_MAX_SESSIONS"},
		{"not a number", "lots", "", 0, 0, "SUPERMCP_MCP_MAX_SESSIONS"},
		{"idle too short", "", "10s", 0, 0, "between 1m0s and 24h0m0s"},
		{"idle not a duration", "", "ten minutes", 0, 0, "is not a duration"},
	}
	t.Setenv("SUPERMCP_MCP_ELICITATION_TIMEOUT", "")
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("DATABASE_URL", "postgres://example.invalid/db")
			t.Setenv("SUPERMCP_PUBLIC_URL", "https://supermcp.example")
			t.Setenv("SUPERMCP_MCP_MAX_SESSIONS", c.max)
			t.Setenv("SUPERMCP_MCP_SESSION_IDLE", c.idle)
			cfg, err := Load("test")
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("err = %v, want one saying %q", err, c.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cfg.MCP.MaxSessions != c.wantMax || cfg.MCP.SessionIdle != c.wantIdle {
				t.Errorf("sessions = %d / %s, want %d / %s", cfg.MCP.MaxSessions, cfg.MCP.SessionIdle, c.wantMax, c.wantIdle)
			}
		})
	}
}

// TestMCPElicitationTimeout cannot run in parallel: it sets the environment.
func TestMCPElicitationTimeout(t *testing.T) {
	cases := []struct {
		value   string
		want    time.Duration
		wantErr string
	}{
		{"", DefaultMCPElicitationTimeout, ""},
		{"30s", 30 * time.Second, ""},
		{"1s", 0, "between 5s and 10m0s"},
		{"1h", 0, "between 5s and 10m0s"},
		{"soon", 0, "is not a duration"},
	}
	for _, c := range cases {
		t.Run(c.value, func(t *testing.T) {
			t.Setenv("DATABASE_URL", "postgres://example.invalid/db")
			t.Setenv("SUPERMCP_PUBLIC_URL", "https://supermcp.example")
			t.Setenv("SUPERMCP_MCP_ELICITATION_TIMEOUT", c.value)
			cfg, err := Load("test")
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("err = %v, want one saying %q", err, c.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cfg.MCP.ElicitationTimeout != c.want {
				t.Errorf("timeout = %s, want %s", cfg.MCP.ElicitationTimeout, c.want)
			}
		})
	}
}
