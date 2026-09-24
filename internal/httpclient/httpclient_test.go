package httpclient

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/supermcpco/supermcp/internal/ssrf"
)

func testClient(t *testing.T, p Policy) *Client {
	t.Helper()
	// httptest listens on loopback; allow it for the test.
	d := ssrf.NewDialer(&ssrf.Policy{AllowLoopback: true})
	return New(d, "test", p)
}

func fastPolicy() Policy {
	p := DefaultPolicy()
	p.Retry.Delays = []time.Duration{time.Millisecond, time.Millisecond, time.Millisecond}
	return p
}

func TestRetryOnTransientStatusOnly(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		if n < 3 {
			w.WriteHeader(503)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()
	c := testClient(t, fastPolicy())
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	resp, err := c.Do(req)
	if err != nil || resp.StatusCode != 200 || atomic.LoadInt32(&calls) != 3 {
		t.Fatalf("resp=%v err=%v calls=%d", resp, err, calls)
	}
	resp.Body.Close()

	// 500 is never retried (write safety).
	atomic.StoreInt32(&calls, 0)
	srv500 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(500)
	}))
	defer srv500.Close()
	req, _ = http.NewRequest(http.MethodPost, srv500.URL, bytes.NewReader([]byte("x")))
	resp, err = c.Do(req)
	if err != nil || resp.StatusCode != 500 || atomic.LoadInt32(&calls) != 1 {
		t.Fatalf("500: resp=%v err=%v calls=%d", resp, err, calls)
	}
	resp.Body.Close()
}

func TestNoRetryWithoutReplayableBody(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(503)
	}))
	defer srv.Close()
	c := testClient(t, fastPolicy())
	pr, pw := io.Pipe()
	go func() { pw.Write([]byte("stream")); pw.Close() }()
	req, _ := http.NewRequest(http.MethodPost, srv.URL, pr) // no GetBody
	resp, err := c.Do(req)
	if err != nil || resp.StatusCode != 503 || atomic.LoadInt32(&calls) != 1 {
		t.Fatalf("resp=%v err=%v calls=%d", resp, err, calls)
	}
	resp.Body.Close()
}

func TestBreakerOpensAfterFailures(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) }))
	defer srv.Close()
	p := fastPolicy()
	p.Breaker = BreakerPolicy{MinRequests: 3, FailureRatio: 0.6, Interval: time.Minute, OpenTimeout: time.Minute, HalfOpenMax: 1}
	c := testClient(t, p)
	for i := 0; i < 3; i++ {
		req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
		resp, err := c.Do(req)
		if err != nil || resp.StatusCode != 500 {
			t.Fatalf("attempt %d: resp=%v err=%v", i, resp, err)
		}
		resp.Body.Close()
	}
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	if _, err := c.Do(req); !errors.Is(err, ErrBreakerOpen) {
		t.Fatalf("expected breaker open, got %v", err)
	}
}

func TestFourXXDoesNotTripBreaker(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(404) }))
	defer srv.Close()
	p := fastPolicy()
	p.Breaker = BreakerPolicy{MinRequests: 2, FailureRatio: 0.5, Interval: time.Minute, OpenTimeout: time.Minute, HalfOpenMax: 1}
	c := testClient(t, p)
	for i := 0; i < 5; i++ {
		req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
		resp, err := c.Do(req)
		if err != nil || resp.StatusCode != 404 {
			t.Fatalf("attempt %d: resp=%v err=%v", i, resp, err)
		}
		resp.Body.Close()
	}
}

func TestResponseSizeLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write(bytes.Repeat([]byte("a"), 2048))
	}))
	defer srv.Close()
	p := fastPolicy()
	p.MaxResponseBytes = 1024
	c := testClient(t, p)
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if _, err := io.ReadAll(resp.Body); !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("expected size limit error, got %v", err)
	}
}

func TestSSRFBlockedIsNotRetried(t *testing.T) {
	d := ssrf.NewDialer(&ssrf.Policy{})
	c := New(d, "test", fastPolicy())
	req, _ := http.NewRequest(http.MethodGet, "http://169.254.169.254/latest/meta-data", nil)
	start := time.Now()
	_, err := c.Do(req)
	if !errors.Is(err, ssrf.ErrBlocked) {
		t.Fatalf("expected ErrBlocked, got %v", err)
	}
	if time.Since(start) > 500*time.Millisecond {
		t.Fatal("blocked request should fail fast, not retry")
	}
}

func TestConcurrencyCap(t *testing.T) {
	var inflight, peak int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := atomic.AddInt32(&inflight, 1)
		for {
			p := atomic.LoadInt32(&peak)
			if n <= p || atomic.CompareAndSwapInt32(&peak, p, n) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
		atomic.AddInt32(&inflight, -1)
		w.WriteHeader(200)
	}))
	defer srv.Close()
	p := fastPolicy()
	p.MaxConcurrent = 2
	c := testClient(t, p)
	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func() {
			req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
			if resp, err := c.Do(req); err == nil {
				resp.Body.Close()
			}
			done <- struct{}{}
		}()
	}
	for i := 0; i < 8; i++ {
		<-done
	}
	if atomic.LoadInt32(&peak) > 2 {
		t.Fatalf("peak concurrency %d exceeded cap", peak)
	}
}
