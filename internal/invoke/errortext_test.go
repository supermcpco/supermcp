package invoke

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/supermcpco/supermcp/internal/engine"
)

// TestErrorTextKeepsNoCredential checks what a failed call leaves on its
// invocation row and in its audit event: no credential a URL or DSN
// carried, and nothing the masked payload policy would have removed from
// the arguments.
func TestErrorTextKeepsNoCredential(t *testing.T) {
	t.Parallel()
	transport := engine.ScrubURLError(fmt.Errorf("upstream unavailable after 3 attempts: %w", &url.Error{
		Op: "Get", URL: "https://api.example.com/v1/items?id=42&access=qk-3f9a8e7d6c5b", Err: errors.New("connection refused"), // gitleaks:allow
	}))
	tests := []struct {
		name  string
		err   error
		leaks []string
		keeps []string
	}{
		{name: "a query key in a transport error", err: transport,
			leaks: []string{"qk-3f9a8e7d6c5b", "id=42"}, keeps: []string{"api.example.com/v1/items", "connection refused"}}, // gitleaks:allow
		{name: "a DSN password", err: errors.New("connect postgres://app:hunter2@db.internal/app: refused"),
			leaks: []string{"hunter2"}, keeps: []string{"db.internal"}},
		{name: "a secret-named query parameter quoted as text", err: errors.New("GET https://x.example/a?api_key=abc123 failed"),
			leaks: []string{"abc123"}},
		{name: "an argument the caller sent", err: errors.New("no user alice@example.com, card 4111 1111 1111 1111"),
			leaks: []string{"alice@example.com", "4111 1111 1111 1111"}, keeps: []string{"no user"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := errorText(tt.err)
			for _, s := range tt.leaks {
				if strings.Contains(got, s) {
					t.Errorf("errorText kept %q: %s", s, got)
				}
			}
			for _, s := range tt.keeps {
				if !strings.Contains(got, s) {
					t.Errorf("errorText lost %q, which says what went wrong: %s", s, got)
				}
			}
		})
	}
}
