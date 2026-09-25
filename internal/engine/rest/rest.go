// Package rest executes http-transport tools. Request building reproduces
// the legacy engine's wire format byte for byte where adapters depend on it:
// query encoding that leaves ':', '$' and ',' unescaped and writes spaces
// as '+', repeated keys for arrays, PHP-style bracket form bodies, and the
// __raw / __rawquery / __spread escape hatches.
package rest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/clbanning/mxj/v2"

	"github.com/supermcpco/supermcp/internal/engine"
	"github.com/supermcpco/supermcp/pkg/adapter"
	"github.com/supermcpco/supermcp/pkg/tmpl"
)

// Engine is the http engine.
type Engine struct{}

func (Engine) Type() adapter.TransportType { return adapter.TransportHTTP }

// built is a fully rendered request.
type built struct {
	method  string
	url     string
	headers http.Header
	body    []byte
	getBody func() (io.ReadCloser, error)
}

// Execute sends the request. A 401 triggers one credential refresh and one
// retry when the authenticator supports it.
func (e Engine) Execute(ctx context.Context, req *engine.Request) (*engine.Response, error) {
	if req.HTTP == nil {
		return nil, errors.New("rest: no HTTP client")
	}
	b, err := build(req)
	if err != nil {
		return nil, err
	}
	resp, meta, err := e.send(ctx, req, b) //nolint:bodyclose // closed by drain or decode
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		if r, ok := req.Auth.(engine.Refresher); ok {
			drain(resp)
			retry, rerr := r.Refresh(ctx)
			if rerr != nil {
				return nil, fmt.Errorf("credential refresh after 401: %w", rerr)
			}
			if retry {
				meta.AuthRefreshed = true
				resp, _, err = e.send(ctx, req, b) //nolint:bodyclose // closed by decode
				if err != nil {
					return nil, err
				}
			}
		}
	}
	return decode(resp, req, meta)
}

// DryRun renders the request with secrets redacted.
func (Engine) DryRun(_ context.Context, req *engine.Request) (*engine.Preview, error) {
	b, err := build(req)
	if err != nil {
		return nil, err
	}
	p := &engine.Preview{Method: b.method, URL: b.url, Headers: map[string]string{}}
	for k := range b.headers {
		v := b.headers.Get(k)
		if isSensitiveHeader(k) {
			v = "<redacted>"
		}
		p.Headers[k] = v
	}
	if len(b.body) > 0 {
		p.Body = string(b.body)
	}
	return p, nil
}

func isSensitiveHeader(k string) bool {
	k = strings.ToLower(k)
	return k == "authorization" || k == "cookie" || k == "proxy-authorization" || strings.Contains(k, "api-key") || strings.Contains(k, "apikey") || strings.Contains(k, "token") || strings.Contains(k, "secret") || strings.Contains(k, "signature")
}

func (Engine) send(ctx context.Context, req *engine.Request, b *built) (*http.Response, engine.Meta, error) {
	var meta engine.Meta
	hreq, err := http.NewRequestWithContext(ctx, b.method, b.url, nil)
	if err != nil {
		return nil, meta, engine.ScrubURLError(err)
	}
	if len(b.body) > 0 {
		hreq.Body = io.NopCloser(bytes.NewReader(b.body))
		hreq.GetBody = b.getBody
		hreq.ContentLength = int64(len(b.body))
	}
	for k, vs := range b.headers {
		for _, v := range vs {
			hreq.Header.Add(k, v)
		}
	}
	if req.Auth != nil {
		if err := req.Auth.Apply(ctx, hreq); err != nil {
			return nil, meta, fmt.Errorf("apply auth: %w", err)
		}
		if s, ok := req.Auth.(engine.Signer); ok {
			if err := s.Sign(ctx, hreq, b.body); err != nil {
				return nil, meta, fmt.Errorf("sign request: %w", err)
			}
		}
	}
	start := time.Now()
	resp, err := req.HTTP.Do(hreq)
	meta.UpstreamDurationMS = time.Since(start).Milliseconds()
	if err != nil {
		return nil, meta, engine.ScrubURLError(err)
	}
	return resp, meta, nil
}

func drain(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	_ = resp.Body.Close()
}

// ---------------------------------------------------------------------------
// request building

func build(req *engine.Request) (*built, error) {
	op := req.Tool.Operation
	vars := req.Vars
	c := req.Connector

	method := strings.ToUpper(op.Method)
	if method == "" {
		method = http.MethodGet
	}

	base, err := tmpl.RenderString(c.BaseURL, vars, tmpl.Strict)
	if err != nil {
		return nil, fmt.Errorf("baseUrl: %w", err)
	}
	path, err := tmpl.RenderString(op.Path, vars, tmpl.Path)
	if err != nil {
		return nil, fmt.Errorf("path: %w", err)
	}
	full := joinBaseAndPath(base, path)

	// Query.
	query := map[string]any{}
	if op.Query != nil && op.Query.N != nil {
		raw, err := op.Query.Value()
		if err != nil {
			return nil, err
		}
		rendered, err := tmpl.RenderValue(raw, vars)
		if err != nil {
			return nil, fmt.Errorf("query: %w", err)
		}
		m, _ := rendered.(map[string]any)
		query = m
		if rq, ok := query["__rawquery"].(string); ok {
			delete(query, "__rawquery")
			if parsed, err := url.ParseQuery(rq); err == nil {
				for k, vs := range parsed {
					if len(vs) == 1 {
						query[k] = vs[0]
					} else {
						list := make([]any, len(vs))
						for i, v := range vs {
							list[i] = v
						}
						query[k] = list
					}
				}
			}
		}
	}
	if qs := EncodeQuery(query, orderedKeys(op.Query)); qs != "" {
		if strings.Contains(full, "?") {
			full += "&" + qs
		} else {
			full += "?" + qs
		}
	}

	// Headers: connector first, then tool (tool wins).
	headers := http.Header{}
	for _, k := range c.Headers.Keys {
		v, ok, err := tmpl.Render(c.Headers.Values[k], vars, tmpl.Value)
		if err != nil {
			return nil, fmt.Errorf("header %s: %w", k, err)
		}
		if ok {
			headers.Set(k, tmpl.Stringify(v))
		}
	}
	for _, k := range op.Headers.Keys {
		v, ok, err := tmpl.Render(op.Headers.Values[k], vars, tmpl.Value)
		if err != nil {
			return nil, fmt.Errorf("header %s: %w", k, err)
		}
		if ok {
			headers.Set(k, tmpl.Stringify(v))
		}
	}

	b := &built{method: method, url: full, headers: headers}

	// Body.
	if op.Body != nil && op.Body.Value != nil && op.Body.Value.N != nil && method != http.MethodGet && method != http.MethodHead {
		raw, err := op.Body.Value.Value()
		if err != nil {
			return nil, err
		}
		encoding := op.Body.Encoding
		if encoding == "" {
			encoding = "json"
		}
		if encoding == "raw" {
			s, _ := raw.(string)
			out, err := tmpl.RenderString(s, vars, tmpl.Strict)
			if err != nil {
				return nil, fmt.Errorf("body: %w", err)
			}
			b.body = []byte(out)
		} else {
			rendered, err := tmpl.RenderValue(raw, vars)
			if err != nil {
				return nil, fmt.Errorf("body: %w", err)
			}
			if m, ok := rendered.(map[string]any); ok {
				if rawBody, has := m["__raw"]; has {
					b.body = []byte(tmpl.Stringify(rawBody))
					encoding = "raw"
				}
			}
			if encoding != "raw" {
				keys := orderedKeys(op.Body.Value)
				switch encoding {
				case "json":
					b.body, err = jsonBody(rendered)
					if err != nil {
						return nil, err
					}
					if headers.Get("Content-Type") == "" {
						headers.Set("Content-Type", "application/json")
					}
				case "form":
					b.body = []byte(EncodeForm(rendered, keys))
					if headers.Get("Content-Type") == "" {
						headers.Set("Content-Type", "application/x-www-form-urlencoded")
					}
				case "multipart":
					body, ct, err := encodeMultipart(rendered, keys)
					if err != nil {
						return nil, err
					}
					b.body = body
					headers.Set("Content-Type", ct)
				default:
					return nil, fmt.Errorf("unknown body encoding %q", encoding)
				}
			}
		}
		body := b.body
		b.getBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
	}
	return b, nil
}

func orderedKeys(n *adapter.Node) []string {
	if n == nil || n.N == nil {
		return nil
	}
	return adapter.MapKeys(n.N)
}

// joinBaseAndPath joins the connector base and the tool path. An absolute
// path wins outright: a vendor that publishes two hosts under one product
// (Statsig's SDK and console APIs) is one connector with a full URL on the
// tools that live on the other host.
func joinBaseAndPath(base, path string) string {
	if path == "" {
		return base
	}
	if isAbsoluteURL(path) {
		return path
	}
	return strings.TrimRight(base, "/") + "/" + strings.TrimLeft(path, "/")
}

func isAbsoluteURL(s string) bool {
	low := strings.ToLower(s)
	return strings.HasPrefix(low, "http://") || strings.HasPrefix(low, "https://")
}

func jsonBody(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// encodeQueryComponent matches the legacy engine: encodeURIComponent, then ':'
// '$' ',' restored and spaces as '+'. APIs that string-match their own
// filter grammar (OData dates, eBay ranges) depend on it.
func encodeQueryComponent(s string) string {
	// url.QueryEscape encodes like encodeURIComponent except it uses '+' for
	// space already and escapes a few extra characters that
	// encodeURIComponent keeps: ! ' ( ) * ~
	e := url.QueryEscape(s)
	r := strings.NewReplacer("%3A", ":", "%3a", ":", "%24", "$", "%2C", ",", "%2c", ",",
		"%21", "!", "%27", "'", "%28", "(", "%29", ")", "%2A", "*", "%7E", "~")
	return r.Replace(e)
}

// EncodeQuery serialises params with repeated keys for arrays. keys gives
// the authored order; unknown keys (from __rawquery) follow, sorted.
func EncodeQuery(params map[string]any, keys []string) string {
	seen := map[string]bool{}
	var parts []string
	push := func(k string, v any) {
		if v == nil {
			return
		}
		parts = append(parts, encodeQueryComponent(k)+"="+encodeQueryComponent(tmpl.Stringify(v)))
	}
	emit := func(k string) {
		v, ok := params[k]
		if !ok || seen[k] {
			return
		}
		seen[k] = true
		if list, isList := v.([]any); isList {
			for _, e := range list {
				push(k, e)
			}
			return
		}
		push(k, v)
	}
	for _, k := range keys {
		emit(k)
	}
	rest := make([]string, 0)
	for k := range params {
		if !seen[k] {
			rest = append(rest, k)
		}
	}
	sort.Strings(rest)
	for _, k := range rest {
		emit(k)
	}
	return strings.Join(parts, "&")
}

// EncodeForm renders application/x-www-form-urlencoded with PHP-style
// brackets for nested values and the __spread hoist.
func EncodeForm(v any, keys []string) string {
	var pairs []string
	sink := func(k, val string) {
		pairs = append(pairs, url.QueryEscape(k)+"="+url.QueryEscape(val))
	}
	forEachFormEntry(v, keys, func(k string, val any) { appendFormParam(sink, k, val) })
	return strings.Join(pairs, "&")
}

func encodeMultipart(v any, keys []string) ([]byte, string, error) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	var err error
	forEachFormEntry(v, keys, func(k string, val any) {
		appendFormParam(func(key, s string) {
			if err != nil {
				return
			}
			err = w.WriteField(key, s)
		}, k, val)
	})
	if err != nil {
		return nil, "", err
	}
	if err := w.Close(); err != nil {
		return nil, "", err
	}
	return buf.Bytes(), w.FormDataContentType(), nil
}

// forEachFormEntry yields top-level entries in authored order, hoisting
// the entries of a __spread object to the top level.
func forEachFormEntry(v any, keys []string, fn func(string, any)) {
	m, ok := v.(map[string]any)
	if !ok {
		return
	}
	order := append([]string{}, keys...)
	seen := map[string]bool{}
	for _, k := range keys {
		seen[k] = true
	}
	var extra []string
	for k := range m {
		if !seen[k] {
			extra = append(extra, k)
		}
	}
	sort.Strings(extra)
	order = append(order, extra...)
	for _, k := range order {
		val, ok := m[k]
		if !ok {
			continue
		}
		if k == "__spread" {
			if inner, ok := val.(map[string]any); ok {
				ik := make([]string, 0, len(inner))
				for k := range inner {
					ik = append(ik, k)
				}
				sort.Strings(ik)
				for _, k := range ik {
					fn(k, inner[k])
				}
				continue
			}
		}
		fn(k, val)
	}
}

func appendFormParam(sink func(string, string), key string, val any) {
	switch x := val.(type) {
	case nil:
	case []any:
		for i, e := range x {
			appendFormParam(sink, fmt.Sprintf("%s[%d]", key, i), e)
		}
	case map[string]any:
		ks := make([]string, 0, len(x))
		for k := range x {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		for _, k := range ks {
			appendFormParam(sink, key+"["+k+"]", x[k])
		}
	default:
		sink(key, tmpl.Stringify(x))
	}
}

// ---------------------------------------------------------------------------
// response decoding

func decode(resp *http.Response, req *engine.Request, meta engine.Meta) (*engine.Response, error) {
	out := &engine.Response{Status: resp.StatusCode, Meta: meta, Headers: pickHeaders(resp.Header, req.Tool)}
	ct := resp.Header.Get("Content-Type")
	mediaType, _, _ := mime.ParseMediaType(ct)
	out.MediaType = mediaType

	if isBinary(mediaType) {
		out.Stream = resp.Body
		return out, nil
	}
	limit := req.Limits.MaxInlineBytes
	if limit <= 0 {
		limit = 16 << 20
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	_ = resp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("read upstream body: %w", err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("upstream response exceeds %d bytes", limit)
	}
	out.Body = decodeBody(data, mediaType)
	if resp.StatusCode >= 400 {
		return out, &engine.UpstreamError{Status: resp.StatusCode, Body: truncate(string(data), 2000)}
	}
	return out, nil
}

func isBinary(mediaType string) bool {
	switch {
	case strings.HasPrefix(mediaType, "image/"), strings.HasPrefix(mediaType, "audio/"), strings.HasPrefix(mediaType, "video/"):
		return true
	case mediaType == "application/pdf", mediaType == "application/zip", mediaType == "application/octet-stream", mediaType == "application/gzip":
		return true
	}
	return false
}

// decodeBody parses JSON when it looks like JSON, XML when the media type
// says so, and returns text otherwise. Empty bodies decode to nil.
func decodeBody(data []byte, mediaType string) any {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil
	}
	if strings.Contains(mediaType, "json") || (trimmed[0] == '{' || trimmed[0] == '[') {
		var v any
		dec := json.NewDecoder(bytes.NewReader(trimmed))
		dec.UseNumber()
		if err := dec.Decode(&v); err == nil {
			return normaliseNumbers(v)
		}
	}
	if isXML(mediaType) {
		if m, err := mxj.NewMapXml(trimmed); err == nil && len(m) > 0 {
			return map[string]any(m)
		}
	}
	return string(data)
}

func isXML(mediaType string) bool {
	return mediaType == "text/xml" || mediaType == "application/xml" || strings.HasSuffix(mediaType, "+xml")
}

// normaliseNumbers turns json.Number into float64 so JMESPath and the MCP
// encoder see ordinary numbers.
func normaliseNumbers(v any) any {
	switch x := v.(type) {
	case json.Number:
		if f, err := x.Float64(); err == nil {
			return f
		}
		return x.String()
	case map[string]any:
		for k, e := range x {
			x[k] = normaliseNumbers(e)
		}
	case []any:
		for i, e := range x {
			x[i] = normaliseNumbers(e)
		}
	}
	return v
}

func pickHeaders(h http.Header, t *adapter.Tool) map[string]string {
	if t.Response == nil || len(t.Response.ExposeHeaders) == 0 {
		return nil
	}
	out := map[string]string{}
	for _, name := range t.Response.ExposeHeaders {
		if v := h.Get(name); v != "" {
			out[strings.ToLower(name)] = v
		}
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
