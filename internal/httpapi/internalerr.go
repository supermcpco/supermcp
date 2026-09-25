package httpapi

import (
	"context"
	"crypto/rand"
	"log/slog"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/go-chi/chi/v5/middleware"
)

// requestIDHeader is the response header that carries the request id.
const requestIDHeader = "X-Request-Id"

// requestID gives every request an id, puts it where middleware.GetReqID
// finds it (the access log, the error log, the audit trail) and returns it
// in X-Request-Id.
//
// An id the client sends is not taken: the id goes into error messages
// and the audit trail, and a caller must not be able to choose which
// record those point to. chi's own generator is not used either, because
// its ids start with the host name.
func requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := rand.Text()
		w.Header().Set(requestIDHeader, id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), middleware.RequestIDKey, id)))
	})
}

// internalMessage is all a client learns about an error the API has no
// answer for. Driver and upstream errors name hosts, DSN fragments and
// SQL; the request id is how an operator finds them in the log.
func internalMessage(reqID string) string {
	return "something went wrong; the request id is " + reqID
}

// hideInternalErrors is a response transformer that replaces every 500
// with internalMessage and logs what it replaced, once, with the request
// id. A handler that returns an error huma does not recognise gets a 500
// whose errors list carries the error's text; so does one that returns
// humaErr's fallback. Both end here.
func hideInternalErrors(log *slog.Logger) huma.Transformer {
	if log == nil {
		log = slog.Default()
	}
	return func(ctx huma.Context, _ string, v any) (any, error) {
		e, ok := v.(*huma.ErrorModel)
		if !ok || e.Status != http.StatusInternalServerError {
			return v, nil
		}
		rctx := ctx.Context()
		id := middleware.GetReqID(rctx)
		causes := make([]string, 0, len(e.Errors))
		for _, d := range e.Errors {
			if d != nil {
				causes = append(causes, d.Message)
			}
		}
		log.ErrorContext(rctx, "request failed",
			"req_id", id, "method", ctx.Method(), "path", loggedPath(ctx.URL().Path),
			"detail", e.Detail, "err", causes)
		return &huma.ErrorModel{
			Status: http.StatusInternalServerError,
			Title:  http.StatusText(http.StatusInternalServerError),
			Detail: internalMessage(id),
		}, nil
	}
}
