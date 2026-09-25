// Package engine defines how a tool call is executed against an upstream.
//
// One Engine per transport type. Engines receive a fully resolved
// connector, the tool's operation and the caller's arguments, and return a
// decoded response. Authentication is injected by an Authenticator supplied
// by the caller (internal/upstreamauth), so engines never see credentials
// beyond the strings they are told to put on the wire.
package engine

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/supermcpco/supermcp/internal/safeurl"
	"github.com/supermcpco/supermcp/pkg/adapter"
	"github.com/supermcpco/supermcp/pkg/tmpl"
)

// Engine executes tool operations for one transport type.
type Engine interface {
	Type() adapter.TransportType
	Execute(ctx context.Context, req *Request) (*Response, error)
	// DryRun renders the request without sending it. Secrets are redacted.
	DryRun(ctx context.Context, req *Request) (*Preview, error)
}

// Connector is the resolved upstream definition (credentials already
// decrypted and substituted into Vars.Env).
type Connector struct {
	ID       string
	Version  int64 // bumps on any change; keys client/pool caches
	Type     adapter.TransportType
	BaseURL  string
	DSN      string
	Driver   string
	Headers  adapter.OrderedMap[string]
	Auth     adapter.Auth
	Config   map[string]any
	ReadOnly bool // database: refuse non-SELECT statements
}

// Request is one tool call.
type Request struct {
	Connector *Connector
	Tool      *adapter.Tool
	Vars      tmpl.Vars
	Auth      Authenticator // may be nil for auth type none
	HTTP      HTTPDoer      // per-connector client; nil for database
	Limits    Limits
}

// HTTPDoer is satisfied by *httpclient.Client and *http.Client.
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// Limits bound one execution.
type Limits struct {
	MaxRows        int   // database
	MaxInlineBytes int64 // responses larger than this are returned as Stream
}

// Response is the decoded upstream result.
type Response struct {
	Body      any           // decoded JSON, parsed XML map, rows, or text
	Stream    io.ReadCloser // binary / oversized body; MediaType set
	MediaType string
	Status    int
	Headers   map[string]string // only exposeHeaders, lower-cased keys
	Meta      Meta
}

// Meta is execution metadata for audit and metrics.
type Meta struct {
	UpstreamDurationMS int64
	Retries            int
	RowCount           int
	Truncated          bool
	AuthRefreshed      bool
}

// Preview is a dry-run rendering.
type Preview struct {
	Method  string            `json:"method,omitempty"`
	URL     string            `json:"url,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`
	SQL     string            `json:"sql,omitempty"`
	Args    []any             `json:"args,omitempty"`
	// Note says what the preview could not show, and why. A dry run that
	// silently left out the credential would be read as "this call sends
	// no credential".
	Note string `json:"note,omitempty"`
}

// Authenticator applies upstream credentials to a request before the body
// is final. Implementations may also satisfy Signer or Refresher.
type Authenticator interface {
	Apply(ctx context.Context, req *http.Request) error
}

// Signer signs a request once URL and body are final (OAuth 1.0a, HMAC).
type Signer interface {
	Sign(ctx context.Context, req *http.Request, body []byte) error
}

// Refresher can obtain fresh credentials after a 401. retry reports
// whether the request should be sent again.
type Refresher interface {
	Refresh(ctx context.Context) (retry bool, err error)
}

// UpstreamError is a non-2xx response the engine could not use.
type UpstreamError struct {
	Status int
	Body   string
	Hint   string
}

func (e *UpstreamError) Error() string {
	if e.Hint != "" {
		return "upstream returned " + http.StatusText(e.Status) + ": " + e.Hint
	}
	return "upstream returned " + http.StatusText(e.Status)
}

// ScrubURLError returns err with the URL its *url.Error names reduced to
// what may be shown (safeurl.Display), in the *url.Error itself and in the
// message of every error wrapped around it.
//
// net/http names the full request URL in every transport error and
// redacts only a password in it. By the time a request is sent its query
// can carry an API key (an apiKey credential "in: query", or a template
// that renders one), and the error goes on to the tool-call record, the
// audit trail and the caller. So every engine passes a send error through
// here before it goes anywhere.
//
// Rewriting the *url.Error alone is not enough: a wrapper made with
// fmt.Errorf, such as the HTTP client's "upstream unavailable after N
// attempts", fixed its message when it was made. So the returned error
// carries the whole message with the URL replaced, and unwraps to err, so
// errors.Is and errors.As see what they saw before.
func ScrubURLError(err error) error {
	var ue *url.Error
	if !errors.As(err, &ue) || ue.URL == "" {
		return err
	}
	raw := ue.URL
	shown := safeurl.Display(raw)
	ue.URL = shown
	quoted := strconv.Quote(raw)
	msg := strings.ReplaceAll(err.Error(), quoted[1:len(quoted)-1], shown)
	msg = strings.ReplaceAll(msg, raw, shown)
	return &scrubbedError{msg: msg, err: err}
}

type scrubbedError struct {
	msg string
	err error
}

func (e *scrubbedError) Error() string { return e.msg }
func (e *scrubbedError) Unwrap() error { return e.err }

// ErrUnsupported is returned by engines for operations they do not handle.
var ErrUnsupported = errors.New("operation not supported by this engine")
