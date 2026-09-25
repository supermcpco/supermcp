package httpapi

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"

	"github.com/danielgtaylor/huma/v2"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/supermcpco/supermcp/internal/connector"
	"github.com/supermcpco/supermcp/internal/reqid"
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

// hideInternalErrors is a response transformer that replaces every 500
// with reqid.Message and logs what it replaced, once, with the request
// id. A handler that returns an error huma does not recognise gets a 500
// whose errors list carries the error's text; so does one that returns
// humaErr's fallback. Both end here. The logged text goes through
// connector.RedactText first: a driver error can quote a DSN with its
// password.
func hideInternalErrors(log *slog.Logger) huma.Transformer {
	if log == nil {
		log = slog.Default()
	}
	return func(ctx huma.Context, _ string, v any) (any, error) {
		err, ok := v.(error)
		if !ok {
			return v, nil
		}
		var se huma.StatusError
		if !errors.As(err, &se) || se.GetStatus() != http.StatusInternalServerError {
			return v, nil
		}
		causes := []string{}
		var model *huma.ErrorModel
		if errors.As(err, &model) {
			for _, d := range model.Errors {
				if d != nil {
					causes = append(causes, connector.RedactText(d.Message))
				}
			}
		}
		rctx := ctx.Context()
		id := middleware.GetReqID(rctx)
		log.ErrorContext(rctx, "request failed",
			"req_id", id, "method", ctx.Method(), "path", loggedPath(ctx.URL().Path),
			"detail", connector.RedactText(se.Error()), "err", causes)
		return &huma.ErrorModel{
			Status: http.StatusInternalServerError,
			Title:  http.StatusText(http.StatusInternalServerError),
			Detail: reqid.Message(id),
		}, nil
	}
}

// recoverer turns a panic into the same 500 an unmapped error gets: the
// panic and its stack go to the log with the request id, and the client
// gets reqid.Message. It stands where chi's Recoverer did, and like it
// lets http.ErrAbortHandler through and writes nothing on an upgraded
// connection.
func recoverer(log *slog.Logger) func(http.Handler) http.Handler {
	if log == nil {
		log = slog.Default()
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func(ctx context.Context) {
				rec := recover()
				if rec == nil {
					return
				}
				if rec == http.ErrAbortHandler { //nolint:errorlint // the sentinel is compared as net/http does
					panic(rec)
				}
				id := middleware.GetReqID(ctx)
				log.ErrorContext(ctx, "request panicked",
					"req_id", id, "method", r.Method, "path", loggedPath(r.URL.Path),
					"panic", connector.RedactText(fmt.Sprint(rec)), "stack", string(debug.Stack()))
				if r.Header.Get("Connection") != "Upgrade" {
					writeJSONError(w, http.StatusInternalServerError, reqid.Message(id))
				}
			}(r.Context())
			next.ServeHTTP(w, r)
		})
	}
}

// logger is d.Log, or slog.Default for a Deps a test built by hand.
func (d Deps) logger() *slog.Logger {
	if d.Log == nil {
		return slog.Default()
	}
	return d.Log
}
