package httpapi

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/supermcpco/supermcp/internal/connector"
	"github.com/supermcpco/supermcp/internal/reqid"
	"github.com/supermcpco/supermcp/internal/telemetry"
)

// statusClientClosedRequest is the status a request gets when its caller
// went away before the answer: nginx's 499, which huma itself sets when
// the client disconnects while it writes a body. Nobody reads it; it is
// there for the access log and the request metrics, where it keeps an
// abandoned request out of the 5xx a server fault is counted in.
const statusClientClosedRequest = 499

// clientGone reports whether err is what is left of a request whose
// caller went away: the request's context was cancelled, which net/http
// does when the connection closes or an HTTP/2 stream is reset.
//
// The request's context being cancelled is the test, not the shape of
// err. The caller going away reaches a handler as context.Canceled, as a
// 57014 from the statement Postgres was told to stop, as a closed
// connection, or as a 503 a timeout mapping made of one of those; and by
// the time a huma transformer sees the error it is text. Our own time
// limits are deadlines, never a cancellation of the request's context: a
// query's is on a context derived from it, and the router's 60-second
// limit ends the request's context with context.DeadlineExceeded. So
// neither is taken for the caller going away.
func clientGone(ctx context.Context, err error) bool {
	return err != nil && errors.Is(ctx.Err(), context.Canceled)
}

// cancelledQuery reports whether err is what a statement stopped by its
// context looks like: the context's own error, or the 57014 Postgres
// answers when pgx asks it to cancel.
func cancelledQuery(err error) bool {
	var pgErr *pgconn.PgError
	return errors.Is(err, context.Canceled) || (errors.As(err, &pgErr) && pgErr.Code == pgQueryCanceled)
}

// goneErr maps a query the caller's leaving cancelled to a 503, which
// answerClientGone answers with 499 and logs at INFO. Left unmapped it
// would be a 500, which answerClientGone logs at WARN because a 500 can
// be a bug. Anything else is returned as it is.
func goneErr(ctx context.Context, err error) error {
	if clientGone(ctx, err) && cancelledQuery(err) {
		return huma.Error503ServiceUnavailable("the caller went away and the query was cancelled", err)
	}
	return err
}

// goneAwareContext is the huma.Context every operation runs with. When
// answerClientGone has found the caller gone, it writes the 5xx huma is
// about to send as statusClientClosedRequest: a transformer can replace
// a body but not the status, which huma sets after transforming.
type goneAwareContext struct {
	operationContext
	gone bool
}

// operationContext is huma.Context under a name that does not clash with
// its Context method when embedded.
type operationContext huma.Context

// SetStatus writes code, or statusClientClosedRequest in place of a 5xx
// once the caller is known to be gone.
func (c *goneAwareContext) SetStatus(code int) {
	if c.gone && code >= http.StatusInternalServerError {
		code = statusClientClosedRequest
	}
	c.operationContext.SetStatus(code)
}

// Unwrap returns the adapter's context, for humachi.Unwrap.
func (c *goneAwareContext) Unwrap() huma.Context { return c.operationContext }

// withGoneAwareContext is the huma middleware that gives each operation a
// goneAwareContext.
func withGoneAwareContext(ctx huma.Context, next func(huma.Context)) {
	next(&goneAwareContext{operationContext: ctx})
}

// findGoneAware finds the goneAwareContext under ctx. An operation
// middleware or huma.WithValue wraps the context it is handed, and each
// wrapper huma makes says what it wraps through Unwrap, as humachi.Unwrap
// relies on.
func findGoneAware(ctx huma.Context) (*goneAwareContext, bool) {
	for {
		if g, ok := ctx.(*goneAwareContext); ok {
			return g, true
		}
		u, ok := ctx.(interface{ Unwrap() huma.Context })
		if !ok {
			return nil, false
		}
		ctx = u.Unwrap()
	}
}

// answerClientGone is the first response transformer. A 5xx to a caller
// who has gone is answered with statusClientClosedRequest and the request
// id, logged with client_gone=true, and counted in
// supermcp_http_client_gone_total by route and the status it would have
// had.
//
// A mapped 5xx (a 503 for a query that ran out of time, say) is what the
// caller leaving looks like and is logged at INFO. A 500 is an error
// nothing mapped, possibly a bug, and a caller must not be able to hide
// one by hanging up, so it is logged at WARN. Either way the error's
// text goes to the log, redacted as hideInternalErrors does. The original
// status is orig_status, not status, so a search for status>=500 finds
// server errors and not these.
func answerClientGone(log *slog.Logger, m *telemetry.Metrics) huma.Transformer {
	if log == nil {
		log = slog.Default()
	}
	return func(ctx huma.Context, _ string, v any) (any, error) {
		err, ok := v.(error)
		if !ok {
			return v, nil
		}
		var se huma.StatusError
		if !errors.As(err, &se) || se.GetStatus() < http.StatusInternalServerError {
			return v, nil
		}
		gc, ok := findGoneAware(ctx)
		rctx := ctx.Context()
		if !ok || !clientGone(rctx, err) {
			return v, nil
		}
		gc.gone = true
		orig := se.GetStatus()
		causes := []string{}
		var model *huma.ErrorModel
		if errors.As(err, &model) {
			for _, d := range model.Errors {
				if d != nil {
					causes = append(causes, connector.RedactText(d.Message))
				}
			}
		}
		// logKeyServiceErrors runs after this and no longer sees the key
		// service's own error, so it is logged here.
		var kse *keyServiceError
		if errors.As(err, &kse) && kse.cause != nil {
			causes = append(causes, connector.RedactText(kse.cause.Error()))
		}
		level := slog.LevelInfo
		if orig == http.StatusInternalServerError {
			level = slog.LevelWarn
		}
		route := ""
		if rc := chi.RouteContext(rctx); rc != nil {
			route = rc.RoutePattern()
		}
		m.ObserveHTTPClientGone(route, orig)
		id := middleware.GetReqID(rctx)
		log.Log(rctx, level, "request abandoned by the client",
			"req_id", id, "method", ctx.Method(), "path", loggedPath(ctx.URL().Path),
			"client_gone", true, "orig_status", orig,
			"detail", connector.RedactText(se.Error()), "err", causes)
		return &huma.ErrorModel{
			Status: statusClientClosedRequest,
			Title:  "Client Closed Request",
			Detail: reqid.Message(id),
		}, nil
	}
}
