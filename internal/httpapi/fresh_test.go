package httpapi

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/supermcpco/supermcp/internal/authz"
)

func TestFresh(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	window := 5 * time.Minute
	session := func(at time.Time) *authz.Principal {
		return &authz.Principal{Kind: authz.KindUser, AuthMethod: "session", SessionID: "s",
			SignIn: authz.SignIn{At: at, Method: "password"}}
	}
	cases := []struct {
		name string
		p    *authz.Principal
		want bool
	}{
		{"signed in a moment ago", session(now.Add(-time.Second)), true},
		{"at the edge of the window", session(now.Add(-window)), true},
		{"past the window", session(now.Add(-window - time.Second)), false},
		{"a session with no recorded sign-in", session(time.Time{}), false},
		{"an API key", &authz.Principal{Kind: authz.KindAPIKey, AuthMethod: "api_key"}, true},
		{"an OAuth access token", &authz.Principal{Kind: authz.KindUser, AuthMethod: "oauth_at"}, true},
		{"a service account", &authz.Principal{Kind: authz.KindServiceAccount, AuthMethod: "client_credentials"}, true},
		// Only the named non-interactive credentials are exempt: an empty
		// or unknown method is held to the window, and without a vouched
		// time it fails.
		{"no method at all", &authz.Principal{Kind: authz.KindUser}, false},
		{"a method added later", &authz.Principal{Kind: authz.KindUser, AuthMethod: "webauthn_assertion"}, false},
		{"an unknown method signed in just now", &authz.Principal{Kind: authz.KindUser, AuthMethod: "future",
			SignIn: authz.SignIn{At: now.Add(-time.Second)}}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if got := fresh(c.p, window, now); got != c.want {
				t.Errorf("fresh = %v, want %v", got, c.want)
			}
		})
	}
}

func TestErrReauthRequired(t *testing.T) {
	t.Parallel()
	var model *huma.ErrorModel
	if !errors.As(errReauthRequired(5*time.Minute), &model) {
		t.Fatal("the refusal is not a huma error model")
	}
	if model.Status != http.StatusForbidden {
		t.Errorf("status %d, want 403", model.Status)
	}
	if !strings.HasPrefix(model.Detail, "reauth_required: ") || !strings.Contains(model.Detail, "5 minutes") {
		t.Errorf("detail %q", model.Detail)
	}
	if len(model.Errors) != 1 || model.Errors[0].Value != "reauth_required" {
		t.Errorf("errors %+v, want one carrying the code", model.Errors)
	}
}

func TestHumanWindow(t *testing.T) {
	t.Parallel()
	for d, want := range map[time.Duration]string{
		time.Minute: "minute", 5 * time.Minute: "5 minutes", time.Hour: "hour", 2 * time.Hour: "2 hours",
		90 * time.Second: "1m30s",
	} {
		if got := humanWindow(d); got != want {
			t.Errorf("humanWindow(%s) = %q, want %q", d, got, want)
		}
	}
}

func TestVouchedTime(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	earlier, later := now.Add(-time.Minute), now.Add(time.Minute)
	if got := vouchedTime(nil, now); !got.IsZero() {
		t.Errorf("no time = %v, want zero", got)
	}
	if got := vouchedTime(&earlier, now); !got.Equal(earlier) {
		t.Errorf("an earlier time = %v, want it as said", got)
	}
	if got := vouchedTime(&later, now); !got.Equal(now) {
		t.Errorf("a time ahead of the clock = %v, want now", got)
	}
}
