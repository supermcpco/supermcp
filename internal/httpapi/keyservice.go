package httpapi

import (
	"log/slog"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/go-chi/chi/v5/middleware"
)

// keyServiceMessage is all a caller learns when the key service is out of
// reach. The provider's own error names the key, the region and the AWS
// request id; those go to the log, not to the client.
const keyServiceMessage = "the key service that protects stored secrets is unavailable; nothing was changed, try again shortly"

// keyServiceError is the 503 humaErr returns for
// secrets.ErrKeyServiceUnavailable. It renders as the plain error model
// and carries the cause beside it, so logKeyServiceErrors can log what
// the key service said, with the request id, without it reaching the body.
type keyServiceError struct {
	*huma.ErrorModel
	cause error
}

// Unwrap returns the key service failure.
func (e *keyServiceError) Unwrap() error { return e.cause }

// newKeyServiceError builds the 503 for err.
func newKeyServiceError(err error) *keyServiceError {
	return &keyServiceError{
		ErrorModel: &huma.ErrorModel{
			Status: http.StatusServiceUnavailable,
			Title:  http.StatusText(http.StatusServiceUnavailable),
			Detail: keyServiceMessage,
		},
		cause: err,
	}
}

// logKeyServiceErrors is a response transformer that logs the cause of a
// keyServiceError and hands on the bare error model in its place. It runs
// first, so the transformers after it see the type they know.
func logKeyServiceErrors(log *slog.Logger) huma.Transformer {
	if log == nil {
		log = slog.Default()
	}
	return func(ctx huma.Context, _ string, v any) (any, error) {
		e, ok := v.(*keyServiceError)
		if !ok {
			return v, nil
		}
		rctx := ctx.Context()
		log.ErrorContext(rctx, "key service unavailable",
			"req_id", middleware.GetReqID(rctx),
			"method", ctx.Method(), "path", ctx.URL().Path,
			"err", e.cause)
		return e.ErrorModel, nil
	}
}
