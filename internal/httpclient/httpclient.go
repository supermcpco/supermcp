// Package httpclient builds the *http.Client used for every upstream call.
//
// One client per connector: its own pooled transport, timeouts, a circuit
// breaker, a concurrency cap and a retry policy. The transport dials
// through the SSRF guard. Callers wrap requests with Do so that the
// semaphore, breaker and retries apply in that order.
package httpclient

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/sony/gobreaker/v2"
	"golang.org/x/sync/semaphore"

	"github.com/supermcpco/supermcp/internal/ssrf"
)

// Policy is the per-connector network policy.
type Policy struct {
	ConnectTimeout        time.Duration
	TLSHandshakeTimeout   time.Duration
	ResponseHeaderTimeout time.Duration
	TotalTimeout          time.Duration
	MaxConcurrent         int64
	MaxIdleConnsPerHost   int
	MaxResponseBytes      int64
	MaxRedirects          int
	Retry                 RetryPolicy
	Breaker               BreakerPolicy
	Proxy                 *url.URL    // outbound proxy (e.g. unblocker); nil = none
	InsecureSkipVerify    bool        // only meaningful with Proxy (unblocker MITM)
	TLS                   *tls.Config // client certificates (mTLS)
	// OnStateChange reports breaker transitions. The Factory fills it in
	// from its own callback, so a caller building a policy by hand need
	// not know about it.
	OnStateChange StateFunc
}

// BreakerState is a breaker's state as a small integer: 0 closed, 1
// half-open, 2 open. It exists so a caller can report the state without
// importing the breaker library, and it is numbered to match the gauge
// that publishes it.
type BreakerState int

const (
	BreakerClosed BreakerState = iota
	BreakerHalfOpen
	BreakerOpen
)

// StateFunc is called on every breaker transition, with the name the
// client was built under (the connector id). It runs on the request path,
// so it must not block: set a gauge, do not write a row.
type StateFunc func(name string, state BreakerState)

// RetryPolicy retries transient failures with fixed delays.
type RetryPolicy struct {
	Delays   []time.Duration
	Statuses map[int]bool
}

// BreakerPolicy trips a connector's breaker after sustained failure.
type BreakerPolicy struct {
	MinRequests  uint32
	FailureRatio float64
	Interval     time.Duration
	OpenTimeout  time.Duration
	HalfOpenMax  uint32
}

// DefaultPolicy is the policy adapters were written against: 30s total, three
// retries on 421/429/502/503/504 and connection errors, never on 500.
func DefaultPolicy() Policy {
	return Policy{
		ConnectTimeout:        10 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		TotalTimeout:          30 * time.Second,
		MaxConcurrent:         32,
		MaxIdleConnsPerHost:   16,
		MaxResponseBytes:      16 << 20,
		MaxRedirects:          5,
		Retry: RetryPolicy{
			Delays:   []time.Duration{300 * time.Millisecond, 900 * time.Millisecond, 2500 * time.Millisecond},
			Statuses: map[int]bool{421: true, 429: true, 502: true, 503: true, 504: true},
		},
		Breaker: BreakerPolicy{MinRequests: 10, FailureRatio: 0.6, Interval: 60 * time.Second, OpenTimeout: 30 * time.Second, HalfOpenMax: 5},
	}
}

// ErrBreakerOpen is returned when the connector's breaker is open.
var ErrBreakerOpen = errors.New("upstream circuit breaker open")

// Client is a per-connector HTTP client.
type Client struct {
	HTTP    *http.Client
	policy  Policy
	sem     *semaphore.Weighted
	breaker *gobreaker.CircuitBreaker[*http.Response]
	dialer  *ssrf.Dialer
}

// Factory caches clients by connector id + version.
type Factory struct {
	// OnBreakerState is given to every client the factory builds. Set it
	// once, before the first request: it is read when a client is built.
	OnBreakerState StateFunc

	dialer *ssrf.Dialer
	mu     sync.Mutex
	items  map[string]*entry
}

type entry struct {
	version  int64
	client   *Client
	lastUsed time.Time
}

// NewFactory builds a factory using the given SSRF dialer.
func NewFactory(d *ssrf.Dialer) *Factory {
	return &Factory{dialer: d, items: map[string]*entry{}}
}

// For returns the client for a connector, rebuilding it when the version
// changes (credentials, proxy or TLS settings changed).
func (f *Factory) For(id string, version int64, p Policy) *Client {
	f.mu.Lock()
	defer f.mu.Unlock()
	if e, ok := f.items[id]; ok && e.version == version {
		e.lastUsed = time.Now()
		return e.client
	}
	if e, ok := f.items[id]; ok {
		e.client.HTTP.CloseIdleConnections()
	}
	if p.OnStateChange == nil {
		p.OnStateChange = f.OnBreakerState
	}
	c := New(f.dialer, id, p)
	f.items[id] = &entry{version: version, client: c, lastUsed: time.Now()}
	return c
}

// Invalidate drops a connector's client.
func (f *Factory) Invalidate(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if e, ok := f.items[id]; ok {
		e.client.HTTP.CloseIdleConnections()
		delete(f.items, id)
	}
}

// Sweep closes clients idle for longer than maxIdle.
func (f *Factory) Sweep(maxIdle time.Duration) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for id, e := range f.items {
		if time.Since(e.lastUsed) > maxIdle {
			e.client.HTTP.CloseIdleConnections()
			delete(f.items, id)
			n++
		}
	}
	return n
}

// New builds a client with its own transport.
func New(d *ssrf.Dialer, name string, p Policy) *Client {
	base := *d
	base.Base = &net.Dialer{Timeout: p.ConnectTimeout, KeepAlive: 30 * time.Second}
	tr := &http.Transport{
		DialContext:           base.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          p.MaxIdleConnsPerHost * 4,
		MaxIdleConnsPerHost:   p.MaxIdleConnsPerHost,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   p.TLSHandshakeTimeout,
		ResponseHeaderTimeout: p.ResponseHeaderTimeout,
		ExpectContinueTimeout: time.Second,
	}
	if p.TLS != nil {
		tr.TLSClientConfig = p.TLS.Clone()
	}
	if p.Proxy != nil {
		tr.Proxy = http.ProxyURL(p.Proxy)
		if p.InsecureSkipVerify {
			if tr.TLSClientConfig == nil {
				tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
			}
			tr.TLSClientConfig.InsecureSkipVerify = true //nolint:gosec // opt-in per connector for MITM unblocker proxies
		}
	}
	c := &Client{policy: p, dialer: d}
	c.HTTP = &http.Client{
		Transport: tr,
		Timeout:   p.TotalTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= p.MaxRedirects {
				return fmt.Errorf("stopped after %d redirects", p.MaxRedirects)
			}
			// The dialer re-checks the new host; nothing else to do here.
			return nil
		},
	}
	if p.MaxConcurrent > 0 {
		c.sem = semaphore.NewWeighted(p.MaxConcurrent)
	}
	bp := p.Breaker
	if bp.MinRequests > 0 {
		settings := gobreaker.Settings{
			Name:        name,
			MaxRequests: bp.HalfOpenMax,
			Interval:    bp.Interval,
			Timeout:     bp.OpenTimeout,
			ReadyToTrip: func(counts gobreaker.Counts) bool {
				return counts.Requests >= bp.MinRequests && float64(counts.TotalFailures)/float64(counts.Requests) >= bp.FailureRatio
			},
			IsSuccessful: func(err error) bool {
				// 4xx are the caller's problem, not upstream health.
				var ue *upstreamError
				return err == nil || (errors.As(err, &ue) && ue.status < 500)
			},
		}
		if report := p.OnStateChange; report != nil {
			settings.OnStateChange = func(name string, _, to gobreaker.State) {
				report(name, stateOf(to))
			}
		}
		c.breaker = gobreaker.NewCircuitBreaker[*http.Response](settings) //nolint:bodyclose // responses flow to the caller
	}
	return c
}

func stateOf(s gobreaker.State) BreakerState {
	switch s {
	case gobreaker.StateOpen:
		return BreakerOpen
	case gobreaker.StateHalfOpen:
		return BreakerHalfOpen
	default:
		return BreakerClosed
	}
}

// upstreamError carries a status for the breaker's health accounting only;
// Do never returns it to callers.
type upstreamError struct{ status int }

func (e *upstreamError) Error() string { return fmt.Sprintf("upstream status %d", e.status) }

// Do sends the request under the semaphore, breaker and retry policy. A
// response with any status is returned to the caller (it is the engine's
// job to interpret it). Retries only happen when the request body can be
// replayed (req.GetBody set or no body).
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	ctx := req.Context()
	if c.sem != nil {
		if err := c.sem.Acquire(ctx, 1); err != nil {
			return nil, err
		}
		defer c.sem.Release(1)
	}
	do := func() (*http.Response, error) {
		return c.doWithRetry(req)
	}
	if c.breaker == nil {
		return do()
	}
	resp, err := c.breaker.Execute(func() (*http.Response, error) {
		resp, err := do()
		if err != nil {
			return nil, err
		}
		if resp.StatusCode >= 500 {
			// Count as a failure for the breaker but hand the response back.
			return resp, &upstreamError{status: resp.StatusCode}
		}
		return resp, nil
	})
	var ue *upstreamError
	switch {
	case errors.Is(err, gobreaker.ErrOpenState), errors.Is(err, gobreaker.ErrTooManyRequests):
		return nil, ErrBreakerOpen
	case errors.As(err, &ue):
		return resp, nil
	}
	return resp, err
}

func (c *Client) doWithRetry(req *http.Request) (*http.Response, error) {
	replayable := req.Body == nil || req.Body == http.NoBody || req.GetBody != nil
	attempts := 1
	if replayable {
		attempts += len(c.policy.Retry.Delays)
	}
	var lastErr error
	for i := 0; i < attempts; i++ {
		if i > 0 {
			if req.GetBody != nil {
				body, err := req.GetBody()
				if err != nil {
					return nil, err
				}
				req.Body = body
			}
			select {
			case <-req.Context().Done():
				return nil, req.Context().Err()
			case <-time.After(c.policy.Retry.Delays[i-1]):
			}
		}
		resp, err := c.HTTP.Do(req) //nolint:bodyclose // returned to the caller, or drained on retry
		if err != nil {
			lastErr = err
			if !transientErr(err) || req.Context().Err() != nil {
				return nil, err
			}
			continue
		}
		if c.policy.Retry.Statuses[resp.StatusCode] && i < attempts-1 {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
			_ = resp.Body.Close()
			lastErr = &upstreamError{status: resp.StatusCode}
			continue
		}
		if c.policy.MaxResponseBytes > 0 {
			resp.Body = &limitedBody{ReadCloser: resp.Body, n: c.policy.MaxResponseBytes}
		}
		return resp, nil
	}
	return nil, fmt.Errorf("upstream unavailable after %d attempts: %w", attempts, lastErr)
}

// ErrResponseTooLarge is returned when a body exceeds MaxResponseBytes.
var ErrResponseTooLarge = errors.New("upstream response exceeds size limit")

type limitedBody struct {
	io.ReadCloser
	n int64
}

func (l *limitedBody) Read(p []byte) (int, error) {
	if l.n <= 0 {
		return 0, ErrResponseTooLarge
	}
	if int64(len(p)) > l.n+1 {
		p = p[:l.n+1]
	}
	n, err := l.ReadCloser.Read(p)
	l.n -= int64(n)
	if l.n < 0 {
		return n, ErrResponseTooLarge
	}
	return n, err
}

// transientErr reports whether a transport error is worth retrying.
func transientErr(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ssrf.ErrBlocked) {
		return false
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	var oe *net.OpError
	if errors.As(err, &oe) {
		return true // dial/reset/refused
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return dnsErr.IsTemporary || dnsErr.IsTimeout
	}
	return errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF)
}
