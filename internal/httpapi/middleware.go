package httpapi

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/supermcpco/supermcp/internal/hardening"
	"github.com/supermcpco/supermcp/internal/telemetry"
)

// rateLimit charges one request against the caller's budget for the class
// of route it lands on.
//
// It runs after authenticate, so a signed-in caller is limited as a
// principal rather than as an address, and an office behind one NAT is not
// one bucket. A nil limiter passes everything through, which is what a
// test or a cut-down build gets.
func (d Deps) rateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if d.Limiter == nil || isProbe(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		decision, err := d.Limiter.Allow(r.Context(), hardening.Identity(r), d.budgetFor(r.URL.Path))
		if err != nil {
			// A budget that cannot be evaluated is not permission. Failing
			// open here would make an unreachable limiter the cheapest way
			// to turn every budget off.
			if d.Log != nil {
				d.Log.Warn("rate limit budget unavailable, refusing", "path", r.URL.Path, "err", err)
			}
			writeJSONError(w, http.StatusTooManyRequests, "rate limiting is unavailable, try again shortly")
			return
		}
		decision.SetHeaders(w.Header())
		if !decision.Allowed {
			writeJSONError(w, http.StatusTooManyRequests, "too many requests")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// budgetFor picks the budget by path. The middleware runs before chi has
// matched anything, so there is no route pattern to ask for yet; the
// prefixes below are the ones the router is built from.
func (d Deps) budgetFor(path string) hardening.Limit {
	switch {
	// Credential endpoints are attacked slowly and in volume by different
	// people, so they draw on a budget of their own.
	case path == "/api/v1/auth/login", strings.HasPrefix(path, "/api/v1/auth/password"):
		return d.Budgets.SignIn
	case path == "/api/v1/auth/register":
		return d.Budgets.Register
	// Dynamic client registration writes a row per call and needs no
	// credential to reach.
	case path == "/oauth/register":
		return d.Budgets.DCR
	case strings.HasPrefix(path, "/mcp/"):
		return d.Budgets.ToolCall
	}
	return d.Budgets.API
}

// httpMetrics counts finished requests. A nil Metrics records nothing.
func httpMetrics(m *telemetry.Metrics) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if m == nil || isProbe(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			next.ServeHTTP(ww, r)
			// The pattern is only known once the router has matched, which
			// is why it is read on the way out. The raw path carries
			// connector, server and user ids, and would give every one of
			// them a series of its own.
			route := ""
			if rc := chi.RouteContext(r.Context()); rc != nil {
				route = rc.RoutePattern()
			}
			if route == "" {
				// A request refused before the router matched it, by the
				// rate limiter or by CSRF, has no pattern.
				route = coarseRoute(r.URL.Path)
			}
			status := ww.Status()
			if status == 0 {
				// A handler that wrote nothing still sent 200.
				status = http.StatusOK
			}
			m.ObserveHTTPRequest(route, r.Method, status)
		})
	}
}

// coarseRoute labels a request the router never matched, which is what a
// refusal in an earlier middleware looks like from here. It says which
// part of the surface the refusals are landing on, and nothing finer.
//
// The answers are a fixed list rather than a slice of the path, because
// the path is the caller's to choose: anything read out of it, at any
// depth, lets an unauthenticated flood invent a new series per request.
func coarseRoute(path string) string {
	for _, prefix := range []string{"/api/v1", "/mcp", "/oauth", "/scim", "/auth/sso", "/.well-known"} {
		if strings.HasPrefix(path, prefix+"/") || path == prefix {
			return prefix
		}
	}
	return "other"
}

// isProbe reports whether the path is a health check. Probes arrive every
// few seconds from every prober: counting them drowns the traffic an
// operator is looking for, and limiting them takes the instance out of
// rotation for being polled.
func isProbe(path string) bool {
	return path == "/healthz" || path == "/readyz"
}
