package httpapi

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/danielgtaylor/huma/v2/humatest"
)

// TestAuditSearchIsBounded checks q is refused past 200 characters on both
// the list and the export, before anything reaches the database. Unsigned
// requests are used on purpose: a q within the bound gets as far as the
// sign-in check (401), one past it is refused by validation first (422).
func TestAuditSearchIsBounded(t *testing.T) {
	t.Parallel()
	_, api := humatest.New(t)
	Deps{}.auditRoutes(api)

	tests := []struct {
		name string
		path string
		q    string
		want int
	}{
		{name: "list, 200 characters", path: "/api/v1/audit", q: strings.Repeat("a", 200), want: http.StatusUnauthorized},
		{name: "list, 201 characters", path: "/api/v1/audit", q: strings.Repeat("a", 201), want: http.StatusUnprocessableEntity},
		{name: "list, 200 characters of two bytes each", path: "/api/v1/audit", q: strings.Repeat("é", 200), want: http.StatusUnauthorized},
		{name: "export, 200 characters", path: "/api/v1/audit/export", q: strings.Repeat("a", 200), want: http.StatusUnauthorized},
		{name: "export, 201 characters", path: "/api/v1/audit/export", q: strings.Repeat("a", 201), want: http.StatusUnprocessableEntity},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			resp := api.Get(tt.path + "?q=" + url.QueryEscape(tt.q))
			if resp.Code != tt.want {
				t.Errorf("GET %s with a %d-character q answered %d, want %d: %s",
					tt.path, len([]rune(tt.q)), resp.Code, tt.want, resp.Body.String())
			}
		})
	}
}
