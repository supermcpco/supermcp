package httpapi

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/supermcpco/supermcp/internal/connector"
	"github.com/supermcpco/supermcp/internal/reqid"
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

// answerClientGone is the first response transformer. A 5xx to a caller
// who has gone is not a server fault: it is logged at INFO with
// client_gone=true rather than at ERROR, and answered with
// statusClientClosedRequest and the request id. The error's text still
// goes to the log, redacted as hideInternalErrors does, so a real fault
// that happened to coincide with the caller leaving is not lost.
func answerClientGone(log *slog.Logger) huma.Transformer {
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
		gc, ok := ctx.(*goneAwareContext)
		rctx := ctx.Context()
		if !ok || !clientGone(rctx, err) {
			return v, nil
		}
		gc.gone = true
		causes := []string{}
		var model *huma.ErrorModel
		if errors.As(err, &model) {
			for _, d := range model.Errors {
				if d != nil {
					causes = append(causes, connector.RedactText(d.Message))
				}
			}
		}
		id := middleware.GetReqID(rctx)
		log.InfoContext(rctx, "request abandoned by the client",
			"req_id", id, "method", ctx.Method(), "path", loggedPath(ctx.URL().Path),
			"client_gone", true, "status", se.GetStatus(),
			"detail", connector.RedactText(se.Error()), "err", causes)
		return &huma.ErrorModel{
			Status: statusClientClosedRequest,
			Title:  "Client Closed Request",
			Detail: reqid.Message(id),
		}, nil
	}
}
