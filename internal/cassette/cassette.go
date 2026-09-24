// Package cassette records one tool's HTTP exchange beside its adapter and
// replays it without touching the network.
//
// The request-parity harness proves the bytes we would put on the wire. A
// cassette fixes what came back as well, so response decoding and the
// response transform are covered too and an adapter can be proved offline,
// which is what `supermcp adapter test` runs in CI.
//
// One file per tool, at adapters/<region>/<slug>/cassettes/<tool>.yaml.
// An adapter can carry a hundred tools; a single file per adapter would be
// rewritten wholesale every time one tool is re-recorded, so two people
// refreshing two tools would conflict and a review could not see which
// upstream had changed. One file per tool keeps a re-recording to one path
// and lets a tool that disappears take its cassette with it.
//
// Secrets never enter a cassette: values that came from credentials are
// replaced by a marker naming the credential, the headers that carry a
// credential wholesale are dropped, and Save refuses to write a file in
// which a credential value survived either step.
package cassette

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"gopkg.in/yaml.v3"

	"github.com/supermcpco/supermcp/internal/engine"
)

// DirName is the directory holding an adapter's cassettes.
const DirName = "cassettes"

// MarkerPrefix starts every credential marker. It is upper-case ASCII and
// underscores so that a marker survives URL, form and JSON encoding
// unchanged and a replayed request still matches the recorded one.
const MarkerPrefix = "SUPERMCP_CREDENTIAL_"

// DefaultMaxBodyBytes bounds a recorded body. A cassette is committed and
// read by people; a multi-megabyte response belongs in neither.
const DefaultMaxBodyBytes int64 = 256 << 10

// minRedactedLength is the shortest credential value worth substituting. A
// value of three characters or fewer would match innocent text all over a
// response, and is not a secret in the first place.
const minRedactedLength = 4

// Cassette is every recorded exchange for one tool.
type Cassette struct {
	Adapter    string    `yaml:"adapter"`
	Tool       string    `yaml:"tool"`
	RecordedAt time.Time `yaml:"recordedAt"`
	// Credentials are the credentials that had a value when this was
	// recorded. A replay sets those, and only those, to their markers: a
	// credential that was absent shaped the request by its absence, and
	// giving it a value on replay would change the request.
	Credentials  []string      `yaml:"credentials,omitempty"`
	Interactions []Interaction `yaml:"interactions"`
}

// Interaction is one call: the arguments it was made with, the request as
// sent and the response as received.
type Interaction struct {
	Params   map[string]any `yaml:"params,omitempty"`
	Request  Request        `yaml:"request"`
	Response Response       `yaml:"response"`
}

// Request is the request as it went on the wire. URL carries no query
// string: the query is a field of its own because it is matched as a set
// of pairs, and splitting at record time avoids re-encoding it later.
type Request struct {
	Method  string            `yaml:"method"`
	URL     string            `yaml:"url"`
	Query   string            `yaml:"query,omitempty"`
	Headers map[string]string `yaml:"headers,omitempty"`
	Body    string            `yaml:"body,omitempty"`
}

// Response is what came back. Only the headers a replay needs are kept: a
// Date, a request id or a rate-limit counter would make every re-recording
// a diff without telling a reviewer anything.
type Response struct {
	Status  int               `yaml:"status"`
	Headers map[string]string `yaml:"headers,omitempty"`
	Body    string            `yaml:"body,omitempty"`
}

// Diff is one field on which a request and a recorded exchange disagree.
type Diff struct {
	Field string
	Want  string // as recorded
	Have  string // as built now
}

// NoMatchError says which part of the request no recorded exchange could
// account for. "No match" on its own tells whoever is fixing the adapter
// nothing.
type NoMatchError struct {
	Tool     string
	Recorded int
	Diffs    []Diff // against the closest recorded exchange
}

// Options bound what a recording may contain.
type Options struct {
	// KeepResponseHeaders are response headers to record, lower-cased.
	// Content-Type is always kept: decoding depends on it.
	KeepResponseHeaders []string
	// MaxBodyBytes refuses a larger request or response body. Zero means
	// DefaultMaxBodyBytes.
	MaxBodyBytes int64
}

// Secrets redacts credential values and proves that none survived.
type Secrets struct {
	names    []string // credential names, sorted
	forms    map[string][]string
	replacer *strings.Replacer
}

// Recorder wraps the live client, keeps what crossed it and redacts as it
// goes. It is the engine's HTTPDoer, so it sees the request exactly as the
// engine sends it: rendered, authenticated and signed.
type Recorder struct {
	inner   engine.HTTPDoer
	secrets *Secrets
	opts    Options
	keep    map[string]bool

	// mu guards done: the engine may send twice for one call (a 401
	// refresh retries), and a future caller may fan out.
	mu   sync.Mutex
	done []Interaction
}

// Player answers requests from a cassette. It holds no transport and
// therefore cannot reach the network however it is wired up.
type Player struct {
	cassette *Cassette
}

// droppedHeaders carry a credential whole. A cassette that leaks a token is
// worse than one that expires, so these never reach a file.
var droppedHeaders = map[string]bool{
	"authorization":       true,
	"cookie":              true,
	"set-cookie":          true,
	"proxy-authorization": true,
}

// NewSecrets takes credential names mapped to the live values they had
// while recording. Values shorter than minRedactedLength are ignored: see
// the constant.
func NewSecrets(values map[string]string) *Secrets {
	s := &Secrets{forms: map[string][]string{}}
	type substitution struct{ form, marker string }
	var subs []substitution
	for name, v := range values {
		if len(v) < minRedactedLength {
			continue
		}
		s.names = append(s.names, name)
		s.forms[name] = encodings(v)
		for _, form := range s.forms[name] {
			subs = append(subs, substitution{form, Marker(name)})
		}
	}
	sort.Strings(s.names)
	// Longest first, so that one credential that is a prefix of another
	// cannot claim the longer one's occurrences; then by content, because
	// a replacer built in map order would redact differently each run.
	sort.Slice(subs, func(i, j int) bool {
		if len(subs[i].form) != len(subs[j].form) {
			return len(subs[i].form) > len(subs[j].form)
		}
		if subs[i].form != subs[j].form {
			return subs[i].form < subs[j].form
		}
		return subs[i].marker < subs[j].marker
	})
	pairs := make([]string, 0, len(subs)*2)
	for _, sub := range subs {
		pairs = append(pairs, sub.form, sub.marker)
	}
	if len(pairs) > 0 {
		s.replacer = strings.NewReplacer(pairs...)
	}
	return s
}

// NewRecorder wraps a live doer. secrets may be nil when the adapter
// declares no credentials.
func NewRecorder(inner engine.HTTPDoer, secrets *Secrets, opts Options) *Recorder {
	if secrets == nil {
		secrets = NewSecrets(nil)
	}
	if opts.MaxBodyBytes <= 0 {
		opts.MaxBodyBytes = DefaultMaxBodyBytes
	}
	keep := map[string]bool{"content-type": true}
	for _, h := range opts.KeepResponseHeaders {
		keep[strings.ToLower(h)] = true
	}
	return &Recorder{inner: inner, secrets: secrets, opts: opts, keep: keep}
}

// NewPlayer replays c.
func NewPlayer(c *Cassette) *Player { return &Player{cassette: c} }

// Marker is the placeholder a credential's value is replaced by. Replay
// sets the credential to its own marker, so a request built from a marker
// matches the recording byte for byte without any secret existing.
func Marker(name string) string { return MarkerPrefix + name }

// Path is where a tool's cassette lives, given the adapter's directory.
func Path(adapterDir, tool string) string {
	return filepath.Join(adapterDir, DirName, tool+".yaml")
}

// Load reads one cassette.
func Load(path string) (*Cassette, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Cassette
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if c.Tool == "" {
		return nil, fmt.Errorf("%s: cassette names no tool", path)
	}
	return &c, nil
}

// LoadDir reads every cassette in an adapter directory, sorted by tool.
// A directory that does not exist is not an error: most adapters have no
// cassettes yet.
func LoadDir(adapterDir string) ([]*Cassette, error) {
	entries, err := os.ReadDir(filepath.Join(adapterDir, DirName))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []*Cassette
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".yaml" {
			continue
		}
		c, err := Load(filepath.Join(adapterDir, DirName, e.Name()))
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Tool < out[j].Tool })
	return out, nil
}

// Redact replaces every known credential value with its marker.
func (s *Secrets) Redact(text string) string {
	if s == nil || s.replacer == nil {
		return text
	}
	return s.replacer.Replace(text)
}

// RedactMap redacts the values of a header map.
func (s *Secrets) RedactMap(m map[string]string) map[string]string {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = s.Redact(v)
	}
	return out
}

// Verify reports the first credential whose value survived redaction. It
// is the last gate before a cassette is written: substitution can only
// catch the encodings we thought of, so the bytes are checked as well.
func (s *Secrets) Verify(data []byte) error {
	if s == nil {
		return nil
	}
	for _, name := range s.names {
		for _, form := range s.forms[name] {
			if bytes.Contains(data, []byte(form)) {
				return fmt.Errorf("credential %s survived redaction, refusing to write the cassette", name)
			}
		}
	}
	return nil
}

// Save writes the cassette, refusing if a credential value is still in it.
func (c *Cassette) Save(path string, secrets *Secrets) error {
	var buf bytes.Buffer
	buf.WriteString("# Recorded by `supermcp adapter record`; replayed by `supermcp adapter test`.\n")
	buf.WriteString("# Credential values are replaced with " + MarkerPrefix + "<NAME>.\n")
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(c); err != nil {
		return err
	}
	if err := enc.Close(); err != nil {
		return err
	}
	if err := secrets.Verify(buf.Bytes()); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, buf.Bytes(), 0o644)
}

// Match finds the exchange that accounts for a request. The returned error
// names the fields the closest exchange disagreed on.
func (c *Cassette) Match(r Request) (*Interaction, error) {
	var closest []Diff
	for i := range c.Interactions {
		diffs := compare(c.Interactions[i].Request, r)
		if len(diffs) == 0 {
			return &c.Interactions[i], nil
		}
		if closest == nil || len(diffs) < len(closest) {
			closest = diffs
		}
	}
	return nil, &NoMatchError{Tool: c.Tool, Recorded: len(c.Interactions), Diffs: closest}
}

// Do sends the request, records what crossed the wire and hands the
// response on with its body intact.
func (r *Recorder) Do(req *http.Request) (*http.Response, error) {
	sent, err := capture(req, r.opts.MaxBodyBytes)
	if err != nil {
		return nil, err
	}
	resp, err := r.inner.Do(req) //nolint:bodyclose // the body is replaced and returned to the caller
	if err != nil {
		return nil, err
	}
	body, err := readBody(resp.Body, r.opts.MaxBodyBytes)
	if err != nil {
		return nil, fmt.Errorf("record response body: %w", err)
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	if !utf8.Valid(body) {
		return nil, fmt.Errorf("response of %s is not text and cannot be recorded", req.URL.Redacted())
	}

	sent.Headers = r.secrets.RedactMap(sent.Headers)
	sent.URL = r.secrets.Redact(sent.URL)
	sent.Query = r.secrets.Redact(sent.Query)
	sent.Body = r.secrets.Redact(sent.Body)

	r.mu.Lock()
	defer r.mu.Unlock()
	r.done = append(r.done, Interaction{
		Request: sent,
		Response: Response{
			Status:  resp.StatusCode,
			Headers: r.secrets.RedactMap(headerMap(resp.Header, r.keep)),
			Body:    r.secrets.Redact(string(body)),
		},
	})
	return resp, nil
}

// Interactions returns what was recorded, oldest first.
func (r *Recorder) Interactions() []Interaction {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Interaction, len(r.done))
	copy(out, r.done)
	return out
}

// Last returns the most recent exchange. An authentication refresh makes
// the engine send twice for one call, and the second send is the one the
// upstream answered.
func (r *Recorder) Last() (Interaction, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.done) == 0 {
		return Interaction{}, false
	}
	return r.done[len(r.done)-1], true
}

// Do answers from the cassette.
func (p *Player) Do(req *http.Request) (*http.Response, error) {
	sent, err := capture(req, DefaultMaxBodyBytes)
	if err != nil {
		return nil, err
	}
	in, err := p.cassette.Match(sent)
	if err != nil {
		return nil, err
	}
	header := http.Header{}
	for k, v := range in.Response.Headers {
		header.Set(k, v)
	}
	body := []byte(in.Response.Body)
	return &http.Response{
		Status:        fmt.Sprintf("%d %s", in.Response.Status, http.StatusText(in.Response.Status)),
		StatusCode:    in.Response.Status,
		Header:        header,
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       req,
	}, nil
}

func (e *NoMatchError) Error() string {
	if e.Recorded == 0 {
		return fmt.Sprintf("the cassette for %s has no recorded exchanges", e.Tool)
	}
	parts := make([]string, 0, len(e.Diffs))
	for _, d := range e.Diffs {
		parts = append(parts, fmt.Sprintf("%s differs (recorded %q, built %q)",
			d.Field, truncate(d.Want, 300), truncate(d.Have, 300)))
	}
	return fmt.Sprintf("no recorded exchange matches the request built for %s: %s",
		e.Tool, strings.Join(parts, "; "))
}

// ---------------------------------------------------------------------------
// helpers

// compare reports how a request differs from a recorded one, in the order
// a reader would diagnose them: the wrong verb makes the rest moot.
func compare(want, have Request) []Diff {
	var out []Diff
	add := func(field, w, h string) {
		if w != h {
			out = append(out, Diff{Field: field, Want: w, Have: h})
		}
	}
	add("method", strings.ToUpper(want.Method), strings.ToUpper(have.Method))
	add("url", want.URL, have.URL)
	add("query", canonicalQuery(want.Query), canonicalQuery(have.Query))
	add("body", canonicalBody(want.Body, contentType(want.Headers)), canonicalBody(have.Body, contentType(have.Headers)))
	return out
}

// capture reads a request without consuming it: the recorder has to hand
// the same request on to the live client.
func capture(req *http.Request, limit int64) (Request, error) {
	u := *req.URL
	query := u.RawQuery
	u.RawQuery = ""
	out := Request{Method: strings.ToUpper(req.Method), URL: u.String(), Query: query, Headers: map[string]string{}}
	for k := range req.Header {
		if dropHeader(k) {
			continue
		}
		out.Headers[strings.ToLower(k)] = req.Header.Get(k)
	}
	if len(out.Headers) == 0 {
		out.Headers = nil
	}
	body, err := requestBody(req, limit)
	if err != nil {
		return Request{}, err
	}
	out.Body = body
	return out, nil
}

func requestBody(req *http.Request, limit int64) (string, error) {
	if req.Body == nil || req.Body == http.NoBody {
		return "", nil
	}
	if req.GetBody != nil {
		rc, err := req.GetBody()
		if err != nil {
			return "", err
		}
		data, err := readBody(rc, limit)
		if err != nil {
			return "", err
		}
		return string(data), nil
	}
	data, err := readBody(req.Body, limit)
	if err != nil {
		return "", err
	}
	req.Body = io.NopCloser(bytes.NewReader(data))
	return string(data), nil
}

func readBody(rc io.ReadCloser, limit int64) ([]byte, error) {
	defer func() { _ = rc.Close() }()
	data, err := io.ReadAll(io.LimitReader(rc, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("body exceeds %d bytes, which is more than a cassette should hold", limit)
	}
	return data, nil
}

// dropHeader reports whether a header never reaches a cassette. The named
// four carry a credential whole; the rest are dropped on the same
// reasoning as the engine's dry-run redaction, and none of them is matched
// on, so dropping them costs a replay nothing.
func dropHeader(name string) bool {
	k := strings.ToLower(name)
	if droppedHeaders[k] {
		return true
	}
	return strings.Contains(k, "api-key") || strings.Contains(k, "apikey") ||
		strings.Contains(k, "token") || strings.Contains(k, "secret") ||
		strings.Contains(k, "signature") || strings.Contains(k, "password")
}

func headerMap(h http.Header, keep map[string]bool) map[string]string {
	out := map[string]string{}
	for k := range h {
		lower := strings.ToLower(k)
		if !keep[lower] || dropHeader(lower) {
			continue
		}
		out[lower] = h.Get(k)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func contentType(headers map[string]string) string {
	for k, v := range headers {
		if strings.EqualFold(k, "content-type") {
			return v
		}
	}
	return ""
}

// canonicalQuery compares query strings as sets of pairs: two engines, or
// two versions of one, may order parameters differently but must not
// encode them differently.
func canonicalQuery(q string) string {
	if q == "" {
		return ""
	}
	parts := strings.Split(q, "&")
	sort.Strings(parts)
	return strings.Join(parts, "&")
}

// canonicalBody compares JSON by value, form bodies as sets of pairs and
// anything else verbatim. A multipart boundary is replaced: it is random
// per request, so comparing it would fail every replay.
func canonicalBody(body, ct string) string {
	trimmed := strings.TrimSpace(body)
	if trimmed == "" {
		return ""
	}
	mediaType, params, err := mime.ParseMediaType(ct)
	if err == nil && strings.HasPrefix(mediaType, "multipart/") && params["boundary"] != "" {
		return strings.ReplaceAll(trimmed, params["boundary"], "BOUNDARY")
	}
	var v any
	if json.Unmarshal([]byte(trimmed), &v) == nil {
		if out, err := json.Marshal(v); err == nil {
			return string(out)
		}
	}
	if strings.Contains(trimmed, "=") && !strings.HasPrefix(trimmed, "{") {
		return canonicalQuery(trimmed)
	}
	return trimmed
}

// encodings are the forms one credential value can take on the wire: as
// authored, percent-encoded in a query or path, and base64 as a token or
// half of a basic credential.
func encodings(v string) []string {
	forms := []string{
		v,
		url.QueryEscape(v),
		url.PathEscape(v),
		base64.StdEncoding.EncodeToString([]byte(v)),
		base64.RawURLEncoding.EncodeToString([]byte(v)),
	}
	seen := map[string]bool{}
	out := forms[:0]
	for _, f := range forms {
		if f == "" || seen[f] {
			continue
		}
		seen[f] = true
		out = append(out, f)
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
