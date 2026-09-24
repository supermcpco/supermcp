// Package graphql executes graphql-transport tools: one POST with
// {query, variables} per call. GraphQL errors in a 200 response are
// surfaced as an UpstreamError so the model sees the message.
package graphql

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/supermcpco/supermcp/internal/engine"
	"github.com/supermcpco/supermcp/pkg/adapter"
	"github.com/supermcpco/supermcp/pkg/tmpl"
)

// Engine is the graphql engine.
type Engine struct{}

func (Engine) Type() adapter.TransportType { return adapter.TransportGraphQL }

type payload struct {
	Query     string         `json:"query"`
	Variables map[string]any `json:"variables,omitempty"`
}

func build(req *engine.Request) (url string, body []byte, headers http.Header, err error) {
	op := req.Tool.Operation
	switch op.Kind {
	case "query", "mutation", "subscription":
	default:
		return "", nil, nil, fmt.Errorf("graphql: %w: kind %q", engine.ErrUnsupported, op.Kind)
	}
	url, err = tmpl.RenderString(req.Connector.BaseURL, req.Vars, tmpl.Strict)
	if err != nil {
		return "", nil, nil, fmt.Errorf("baseUrl: %w", err)
	}
	doc, err := tmpl.RenderString(op.Document, req.Vars, tmpl.Strict)
	if err != nil {
		return "", nil, nil, fmt.Errorf("document: %w", err)
	}
	p := payload{Query: doc}
	if op.Variables != nil && op.Variables.N != nil {
		raw, err := op.Variables.Value()
		if err != nil {
			return "", nil, nil, err
		}
		rendered, err := tmpl.RenderValue(raw, req.Vars)
		if err != nil {
			return "", nil, nil, fmt.Errorf("variables: %w", err)
		}
		if m, ok := rendered.(map[string]any); ok && len(m) > 0 {
			p.Variables = m
		}
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(p); err != nil {
		return "", nil, nil, err
	}
	body = bytes.TrimRight(buf.Bytes(), "\n")

	headers = http.Header{}
	headers.Set("Content-Type", "application/json")
	headers.Set("Accept", "application/json")
	for _, m := range []adapter.OrderedMap[string]{req.Connector.Headers, op.Headers} {
		for _, k := range m.Keys {
			v, ok, err := tmpl.Render(m.Values[k], req.Vars, tmpl.Value)
			if err != nil {
				return "", nil, nil, fmt.Errorf("header %s: %w", k, err)
			}
			if ok {
				headers.Set(k, tmpl.Stringify(v))
			}
		}
	}
	return url, body, headers, nil
}

// Execute posts the operation, refreshing credentials once on 401.
func (e Engine) Execute(ctx context.Context, req *engine.Request) (*engine.Response, error) {
	if req.HTTP == nil {
		return nil, errors.New("graphql: no HTTP client")
	}
	url, body, headers, err := build(req)
	if err != nil {
		return nil, err
	}
	resp, meta, err := send(ctx, req, url, body, headers)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		if r, ok := req.Auth.(engine.Refresher); ok {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
			_ = resp.Body.Close()
			retry, rerr := r.Refresh(ctx)
			if rerr != nil {
				return nil, fmt.Errorf("credential refresh after 401: %w", rerr)
			}
			if retry {
				meta.AuthRefreshed = true
				resp, _, err = send(ctx, req, url, body, headers) //nolint:bodyclose // closed below
				if err != nil {
					return nil, err
				}
			}
		}
	}
	defer func() { _ = resp.Body.Close() }()
	limit := req.Limits.MaxInlineBytes
	if limit <= 0 {
		limit = 16 << 20
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read upstream body: %w", err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("upstream response exceeds %d bytes", limit)
	}
	out := &engine.Response{Status: resp.StatusCode, MediaType: "application/json", Meta: meta}
	var envelope struct {
		Data   any `json:"data"`
		Errors []struct {
			Message string `json:"message"`
			Path    []any  `json:"path,omitempty"`
		} `json:"errors"`
	}
	if jerr := json.Unmarshal(data, &envelope); jerr != nil || (envelope.Data == nil && len(envelope.Errors) == 0) {
		if resp.StatusCode >= 400 {
			return out, &engine.UpstreamError{Status: resp.StatusCode, Body: truncate(string(data), 2000)}
		}
		out.Body = string(data)
		return out, nil
	}
	if len(envelope.Errors) > 0 {
		msgs := make([]string, len(envelope.Errors))
		for i, e := range envelope.Errors {
			msgs[i] = e.Message
		}
		errText, _ := json.Marshal(msgs)
		out.Body = map[string]any{"data": envelope.Data, "errors": envelope.Errors}
		return out, &engine.UpstreamError{Status: resp.StatusCode, Body: string(errText), Hint: "GraphQL errors: " + string(errText)}
	}
	out.Body = envelope.Data
	return out, nil
}

func send(ctx context.Context, req *engine.Request, url string, body []byte, headers http.Header) (*http.Response, engine.Meta, error) {
	var meta engine.Meta
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, meta, err
	}
	hreq.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
	for k, vs := range headers {
		for _, v := range vs {
			hreq.Header.Add(k, v)
		}
	}
	if req.Auth != nil {
		if err := req.Auth.Apply(ctx, hreq); err != nil {
			return nil, meta, fmt.Errorf("apply auth: %w", err)
		}
		if s, ok := req.Auth.(engine.Signer); ok {
			if err := s.Sign(ctx, hreq, body); err != nil {
				return nil, meta, err
			}
		}
	}
	start := time.Now()
	resp, err := req.HTTP.Do(hreq)
	meta.UpstreamDurationMS = time.Since(start).Milliseconds()
	return resp, meta, err
}

// DryRun renders the POST body.
func (Engine) DryRun(_ context.Context, req *engine.Request) (*engine.Preview, error) {
	url, body, headers, err := build(req)
	if err != nil {
		return nil, err
	}
	p := &engine.Preview{Method: http.MethodPost, URL: url, Headers: map[string]string{}, Body: string(body)}
	for k := range headers {
		p.Headers[k] = headers.Get(k)
	}
	return p, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
