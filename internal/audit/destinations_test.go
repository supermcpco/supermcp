package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// A destination is a wire format: what leaves this process is what a
// receiver's parser has already been configured for, so these tests assert
// the bytes rather than the call.

var fixedTime = time.Date(2026, 3, 4, 5, 6, 7, 890123000, time.UTC)

func sample(seq int64, action, outcome string) Record {
	return Record{
		Seq: seq, ID: fmt.Sprintf("evt-%d", seq), Time: fixedTime,
		Category: CategoryTool, Action: action, Outcome: outcome,
		ActorKind: "user", ActorID: "u_7", ActorDisplay: "ada@example.com",
		TargetKind: "connector", TargetID: "c_1", TargetDisplay: "prod",
		IP: "203.0.113.7", Hash: "abc123",
	}
}

// --- webhook ---

func TestWebhookPostsSignedNDJSON(t *testing.T) {
	t.Parallel()
	var got struct {
		body    []byte
		headers http.Header
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.body, _ = io.ReadAll(r.Body)
		got.headers = r.Header.Clone()
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	dest := &webhookDest{ep: Endpoint{Kind: KindWebhook, URL: srv.URL, Secret: "s3cr3t"}, client: srv.Client()}
	if err := dest.Send(context.Background(), []Record{sample(1, "tool.invoke", Success), sample(2, "tool.invoke", Failure)}); err != nil {
		t.Fatalf("send: %v", err)
	}
	if n := bytes.Count(got.body, []byte("\n")); n != 2 {
		t.Fatalf("body carried %d lines, want one per record:\n%s", n, got.body)
	}
	if ct := got.headers.Get("Content-Type"); ct != "application/x-ndjson" {
		t.Fatalf("content type = %q", ct)
	}
	verifySignature(t, got.headers, got.body, "s3cr3t")
}

// --- Splunk HEC ---

func TestSplunkPostsOneEventPerLine(t *testing.T) {
	t.Parallel()
	var body []byte
	var auth, contentType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		auth = r.Header.Get("Authorization")
		contentType = r.Header.Get("Content-Type")
		_, _ = io.WriteString(w, `{"text":"Success","code":0}`)
	}))
	defer srv.Close()

	dest := &splunkDest{ep: Endpoint{Kind: KindSplunk, URL: srv.URL, Token: "hec-token", Index: "audit"},
		client: srv.Client(), host: "replica-1"}
	if err := dest.Send(context.Background(), []Record{sample(1, "session.create", Success), sample(2, "tool.invoke", Denied)}); err != nil {
		t.Fatalf("send: %v", err)
	}
	if auth != "Splunk hec-token" {
		t.Fatalf("authorization = %q, want the HEC scheme and the token", auth)
	}
	if contentType != "application/json" {
		t.Fatalf("content type = %q", contentType)
	}
	lines := splitLines(body)
	if len(lines) != 2 {
		t.Fatalf("body carried %d lines, want one envelope per record:\n%s", len(lines), body)
	}
	var first splunkEvent
	first.Event = &Record{}
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatalf("the first line is not an HEC envelope: %v", err)
	}
	if want := float64(fixedTime.UnixNano()) / float64(time.Second); first.Time != want {
		t.Fatalf("time = %f, want the event's own time %f", first.Time, want)
	}
	if first.Index != "audit" || first.SourceType != "supermcp:audit" || first.Host != "replica-1" {
		t.Fatalf("envelope metadata = %+v", first)
	}
	if first.Event.Action != "session.create" || first.Event.Seq != 1 {
		t.Fatalf("event = %+v, want the record itself under \"event\"", first.Event)
	}
}

func TestSplunkReportsARejection(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"text":"Invalid token","code":4}`)
	}))
	defer srv.Close()

	dest := &splunkDest{ep: Endpoint{Kind: KindSplunk, URL: srv.URL, Token: "wrong"}, client: srv.Client()}
	err := dest.Send(context.Background(), []Record{sample(1, "session.create", Success)})
	if err == nil {
		t.Fatal("a rejected batch must be reported, or the cursor moves past events nobody took")
	}
	if !strings.Contains(err.Error(), "403") || !strings.Contains(err.Error(), "Invalid token") {
		t.Fatalf("error = %v, want the status and what the collector said", err)
	}
	if strings.Contains(err.Error(), "wrong") {
		t.Fatal("the token must not travel in an error that is stored and shown")
	}
}

// --- OTLP logs ---

func TestOTLPMapsARecordToALogRecord(t *testing.T) {
	t.Parallel()
	var body []byte
	var header string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		header = r.Header.Get("X-Api-Key")
		_, _ = io.WriteString(w, `{"partialSuccess":{}}`)
	}))
	defer srv.Close()

	dest := &otlpDest{ep: Endpoint{Kind: KindOTLP, URL: srv.URL, Headers: map[string]string{"X-Api-Key": "k"}},
		client: srv.Client(), orgID: "org_1"}
	if err := dest.Send(context.Background(), []Record{sample(1, "tool.invoke", Denied)}); err != nil {
		t.Fatalf("send: %v", err)
	}
	if header != "k" {
		t.Fatalf("the configured header did not travel: %q", header)
	}
	var got otlpPayload
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("body is not an OTLP logs request: %v\n%s", err, body)
	}
	if len(got.ResourceLogs) != 1 || len(got.ResourceLogs[0].ScopeLogs) != 1 {
		t.Fatalf("payload shape = %+v", got)
	}
	logs := got.ResourceLogs[0].ScopeLogs[0].LogRecords
	if len(logs) != 1 {
		t.Fatalf("log records = %d, want one per event", len(logs))
	}
	rec := logs[0]
	if rec.TimeUnixNano != strconv.FormatInt(fixedTime.UnixNano(), 10) {
		t.Fatalf("timeUnixNano = %q, want the event's own time", rec.TimeUnixNano)
	}
	// A denial is a warning: nothing failed, something was stopped.
	if rec.SeverityNumber != 13 || rec.SeverityText != "WARN" {
		t.Fatalf("severity = %d/%s, want 13/WARN for a denial", rec.SeverityNumber, rec.SeverityText)
	}
	if rec.Body.String == nil || *rec.Body.String != "tool.invoke denied" {
		t.Fatalf("body = %+v, want the action and the outcome", rec.Body)
	}
	attrs := map[string]string{}
	for _, a := range rec.Attributes {
		switch {
		case a.Value.String != nil:
			attrs[a.Key] = *a.Value.String
		case a.Value.Int != nil:
			attrs[a.Key] = *a.Value.Int
		}
	}
	for key, want := range map[string]string{
		"audit.seq": "1", "audit.id": "evt-1", "audit.action": "tool.invoke", "audit.outcome": Denied,
		"actor.id": "u_7", "target.id": "c_1", "client.address": "203.0.113.7", "audit.hash": "abc123",
	} {
		if attrs[key] != want {
			t.Fatalf("attribute %s = %q, want %q", key, attrs[key], want)
		}
	}
	res := map[string]string{}
	for _, a := range got.ResourceLogs[0].Resource.Attributes {
		if a.Value.String != nil {
			res[a.Key] = *a.Value.String
		}
	}
	if res["service.name"] != vendor || res["supermcp.organization"] != "org_1" {
		t.Fatalf("resource attributes = %v", res)
	}
}

// An OTLP severity is not a syslog severity and neither is CEF's; the
// three scales are easy to confuse and a receiver's alerting depends on
// them, so each mapping is pinned.
func TestSeverityScales(t *testing.T) {
	t.Parallel()
	tests := []struct {
		outcome                      string
		otlp, otlpText, syslog, cefs any
	}{
		{Success, 9, "INFO", 6, 3},
		{Failure, 17, "ERROR", 3, 6},
		{Denied, 13, "WARN", 4, 8},
	}
	for _, tc := range tests {
		t.Run(tc.outcome, func(t *testing.T) {
			t.Parallel()
			n, text := otlpSeverity(tc.outcome)
			if n != tc.otlp || text != tc.otlpText {
				t.Fatalf("otlp severity = %d/%s, want %v/%v", n, text, tc.otlp, tc.otlpText)
			}
			if got := syslogSeverity(tc.outcome); got != tc.syslog {
				t.Fatalf("syslog severity = %d, want %v", got, tc.syslog)
			}
			if got := cefSeverity(tc.outcome); got != tc.cefs {
				t.Fatalf("cef severity = %d, want %v", got, tc.cefs)
			}
		})
	}
}

// --- syslog ---

func TestSyslogWritesOctetCountedRFC5424(t *testing.T) {
	t.Parallel()
	sink := newSyslogSink(t)
	dest := &syslogDest{ep: Endpoint{Kind: KindSyslog, Host: sink.host, Port: sink.port,
		Facility: syslogSecurity, Format: FormatRFC5424}, dial: plainDial, host: "replica-1"}

	if err := dest.Send(context.Background(), []Record{sample(1, "tool.invoke", Success), sample(2, "session.create", Failure)}); err != nil {
		t.Fatalf("send: %v", err)
	}
	frames := sink.frames(t, 2)
	// facility 10, severity 6: <86>.
	if !strings.HasPrefix(frames[0], "<86>1 ") {
		t.Fatalf("first frame = %q, want priority 86 and version 1", frames[0])
	}
	// facility 10, severity 3 for a failure.
	if !strings.HasPrefix(frames[1], "<83>1 ") {
		t.Fatalf("second frame = %q, want priority 83 for a failure", frames[1])
	}
	// <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
	fields := strings.SplitN(frames[0], " ", 8)
	if len(fields) != 8 {
		t.Fatalf("frame does not have the RFC 5424 header fields: %q", frames[0])
	}
	if fields[1] != "2026-03-04T05:06:07.890123Z" {
		t.Fatalf("timestamp = %q, want the event's own time", fields[1])
	}
	if fields[2] != "replica-1" || fields[3] != product || fields[5] != "tool.invoke" {
		t.Fatalf("header = %q, want hostname, app name and the action as the message id", frames[0])
	}
	if fields[4] != "-" || fields[6] != "-" {
		t.Fatalf("process id and structured data = %q/%q, want the nil value", fields[4], fields[6])
	}
	var back Record
	if err := json.Unmarshal([]byte(fields[7]), &back); err != nil {
		t.Fatalf("the rfc5424 payload is not the record as JSON: %v\n%s", err, fields[7])
	}
	if back.Seq != 1 || back.Action != "tool.invoke" {
		t.Fatalf("payload = %+v", back)
	}
}

func TestSyslogWritesCEF(t *testing.T) {
	t.Parallel()
	sink := newSyslogSink(t)
	dest := &syslogDest{ep: Endpoint{Kind: KindSyslog, Host: sink.host, Port: sink.port,
		Facility: 13, Format: FormatCEF}, dial: plainDial, host: "replica-1"}

	// A display name with an equals sign and a newline is the shape that
	// breaks a naive CEF writer: one ends a value, the other ends a line.
	rec := sample(1, "tool.invoke", Denied)
	rec.ActorDisplay = "ada=1\nbob"
	if err := dest.Send(context.Background(), []Record{rec}); err != nil {
		t.Fatalf("send: %v", err)
	}
	frame := sink.frames(t, 1)[0]
	// facility 13, severity 4 for a denial.
	if !strings.HasPrefix(frame, "<108>1 ") {
		t.Fatalf("frame = %q, want priority 108", frame)
	}
	cef := frame[strings.Index(frame, "CEF:"):]
	header := strings.Split(cef, "|")
	if len(header) < 7 || header[0] != "CEF:0" || header[1] != vendor || header[2] != product {
		t.Fatalf("cef header = %q", cef)
	}
	if header[6] != "8" {
		t.Fatalf("cef severity = %q, want 8 for a denial", header[6])
	}
	ext := header[7]
	for _, want := range []string{
		"rt=" + strconv.FormatInt(fixedTime.UnixMilli(), 10),
		"externalId=evt-1", "act=tool.invoke", "outcome=denied", "src=203.0.113.7",
		`suser=ada\=1\nbob`, "cs2Label=targetId", "cs2=c_1", "cn1=1",
	} {
		if !strings.Contains(ext, want) {
			t.Fatalf("extension %q does not contain %q", ext, want)
		}
	}
	if strings.ContainsAny(frame, "\n") {
		t.Fatal("a frame with a raw newline in it splits one event into two at the receiver")
	}
}

// The transport that carries the audit trail off the box is exactly where
// a silent downgrade would be worth the most, so a collector whose
// certificate does not verify is refused rather than shipped to. The
// server here presents a certificate from its own throwaway authority.
func TestSyslogTLSVerifiesTheCollector(t *testing.T) {
	t.Parallel()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	addr := srv.Listener.Addr().(*net.TCPAddr)

	dest := &syslogDest{ep: Endpoint{Kind: KindSyslog, Host: "127.0.0.1", Port: addr.Port, TLS: true,
		Facility: syslogSecurity, Format: FormatRFC5424}, dial: plainDial, host: "replica-1"}
	err := dest.Send(context.Background(), []Record{sample(1, "tool.invoke", Success)})
	if err == nil {
		t.Fatal("a collector presenting an untrusted certificate must not be shipped to")
	}
	if !strings.Contains(err.Error(), "handshake") {
		t.Fatalf("error = %v, want the handshake to be what failed", err)
	}
}

// A destination that cannot be reached must leave the cursor where it was,
// and the next sweep must pick up from there rather than from the end of
// the batch that was refused.
func TestEachDestinationResumesAfterAFailure(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		// build returns a destination and a switch that makes the receiver
		// refuse the first attempt.
		build func(t *testing.T) (destination, func())
	}{
		{"webhook", func(t *testing.T) (destination, func()) {
			dest, refuse := httpRefuser(t, func(url string, c Doer) destination {
				return &webhookDest{ep: Endpoint{Kind: KindWebhook, URL: url, Secret: "s"}, client: c}
			})
			return dest, refuse
		}},
		{"splunk", func(t *testing.T) (destination, func()) {
			return httpRefuser(t, func(url string, c Doer) destination {
				return &splunkDest{ep: Endpoint{Kind: KindSplunk, URL: url, Token: "t"}, client: c}
			})
		}},
		{"otlp", func(t *testing.T) (destination, func()) {
			return httpRefuser(t, func(url string, c Doer) destination {
				return &otlpDest{ep: Endpoint{Kind: KindOTLP, URL: url}, client: c}
			})
		}},
		{"syslog", func(t *testing.T) (destination, func()) {
			sink := newSyslogSink(t)
			var down bool
			dial := func(ctx context.Context, network, address string) (net.Conn, error) {
				if down {
					return nil, errors.New("connection refused")
				}
				return plainDial(ctx, network, address)
			}
			dest := &syslogDest{ep: Endpoint{Kind: KindSyslog, Host: sink.host, Port: sink.port,
				Facility: syslogSecurity, Format: FormatRFC5424}, dial: dial, host: "replica-1"}
			return dest, func() { down = !down }
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dest, toggle := tc.build(t)
			src := &sliceSource{records: []Record{sample(1, "a", Success), sample(2, "b", Success)}}
			d := &delivery{dest: dest}

			toggle() // the receiver is away
			if err := d.ship(context.Background(), 0, src); err == nil {
				t.Fatal("a refused batch must be reported")
			}
			if src.cursor != 0 {
				t.Fatalf("cursor = %d after a refusal, want it left alone", src.cursor)
			}

			toggle() // and back
			if err := d.ship(context.Background(), src.cursor, src); err != nil {
				t.Fatalf("the retry failed: %v", err)
			}
			if src.cursor != 2 {
				t.Fatalf("cursor = %d, want it past both events", src.cursor)
			}
		})
	}
}

// --- configuration ---

func TestEndpointValidate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		ep   Endpoint
		ok   bool
	}{
		{"a webhook needs a secret", Endpoint{Kind: KindWebhook, URL: "https://x.example"}, false},
		{"a webhook", Endpoint{Kind: KindWebhook, URL: "https://x.example", Secret: "s"}, true},
		{"a scheme that is not http", Endpoint{Kind: KindWebhook, URL: "file:///etc/passwd", Secret: "s"}, false},
		{"a url with no host", Endpoint{Kind: KindWebhook, URL: "https://", Secret: "s"}, false},
		{"splunk needs a token", Endpoint{Kind: KindSplunk, URL: "https://x.example"}, false},
		{"splunk", Endpoint{Kind: KindSplunk, URL: "https://x.example:8088/services/collector", Token: "t"}, true},
		{"otlp", Endpoint{Kind: KindOTLP, URL: "http://collector:4318/v1/logs"}, true},
		{"otlp with a broken header name", Endpoint{Kind: KindOTLP, URL: "http://c:4318/v1/logs",
			Headers: map[string]string{"bad\nname": "v"}}, false},
		{"syslog needs a host", Endpoint{Kind: KindSyslog, Port: 514, Format: FormatRFC5424}, false},
		{"syslog", Endpoint{Kind: KindSyslog, Host: "siem", Port: 6514, TLS: true, Format: FormatCEF, Facility: 10}, true},
		{"a port that is not a port", Endpoint{Kind: KindSyslog, Host: "siem", Port: 70000, Format: FormatCEF}, false},
		{"a facility outside the range", Endpoint{Kind: KindSyslog, Host: "siem", Port: 514, Facility: 99, Format: FormatCEF}, false},
		{"a format nobody parses", Endpoint{Kind: KindSyslog, Host: "siem", Port: 514, Format: "xml"}, false},
		{"a kind this build cannot ship to", Endpoint{Kind: "carrier-pigeon"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.ep.Validate()
			if (err == nil) != tc.ok {
				t.Fatalf("validate = %v, want ok %v", err, tc.ok)
			}
		})
	}
}

func TestNormaliseFillsSyslogDefaults(t *testing.T) {
	t.Parallel()
	ep := Endpoint{Kind: KindSyslog, Host: "siem"}
	ep.Normalise()
	if ep.Port != 514 || ep.Format != FormatRFC5424 || ep.Facility != syslogSecurity {
		t.Fatalf("defaults = %+v", ep)
	}
	tls := Endpoint{Kind: KindSyslog, Host: "siem", TLS: true}
	tls.Normalise()
	if tls.Port != 6514 {
		t.Fatalf("a TLS syslog destination defaults to port %d, want 6514", tls.Port)
	}
	empty := Endpoint{URL: "https://x.example", Secret: "s"}
	empty.Normalise()
	if empty.Kind != KindWebhook {
		t.Fatalf("kind = %q, want a configuration without one to stay a webhook", empty.Kind)
	}
}

// Dialling a customer-supplied syslog host without the guard is the thing
// the guard exists to stop, so a sweep without one refuses the row.
func TestSyslogWithoutAGuardedDialerIsRefused(t *testing.T) {
	t.Parallel()
	_, err := newDestination(KindSyslog, Endpoint{Host: "siem", Port: 514}, "org", nil, nil)
	if err == nil {
		t.Fatal("a syslog destination must not be built without a dialer")
	}
	if _, err := newDestination(KindSyslog, Endpoint{Host: "siem", Port: 514}, "org", nil, plainDial); err != nil {
		t.Fatalf("with a dialer: %v", err)
	}
}

func TestDestinationHidesSecrets(t *testing.T) {
	t.Parallel()
	ep := Endpoint{Kind: KindWebhook, URL: "https://user:hunter2@siem.example/ingest", Secret: "s3cr3t"}
	if got := ep.Destination(); strings.Contains(got, "hunter2") {
		t.Fatalf("destination = %q, and a password in a URL is still a password", got)
	}
	// A token in the query or in the path is as much a credential.
	for in, want := range map[string]string{
		"https://siem.example/hec?token=abc123def456":                                       "https://siem.example/hec?***",                             // gitleaks:allow
		"https://hooks.slack.com/services/T0AAAAAAA/B0BBBBBBB/xoxAbCdEfGhIjKlMnOpQrStUv":    "https://hooks.slack.com/services/T0AAAAAAA/B0BBBBBBB/***", // gitleaks:allow
		"https://discord.com/api/webhooks/123456789012345678/Ab3dEfGhIjKlMnOpQrStUvWxYz012": "https://discord.com/api/webhooks/123456789012345678/***",
	} {
		if got := (Endpoint{Kind: KindWebhook, URL: in}).Destination(); got != want {
			t.Errorf("destination of %s = %q, want %q", in, got, want)
		}
	}
	syslog := Endpoint{Kind: KindSyslog, Host: "siem.example", Port: 6514, TLS: true}
	if got := syslog.Destination(); got != "syslog+tls://siem.example:6514" {
		t.Fatalf("destination = %q", got)
	}
}

// --- helpers ---

func plainDial(ctx context.Context, network, address string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, address)
}

// httpRefuser builds an HTTP destination whose receiver can be switched
// between taking a batch and refusing it.
func httpRefuser(t *testing.T, build func(url string, client Doer) destination) (destination, func()) {
	t.Helper()
	var mu sync.Mutex
	refusing := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if refusing {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return build(srv.URL, srv.Client()), func() {
		mu.Lock()
		defer mu.Unlock()
		refusing = !refusing
	}
}

// syslogSink is a collector: it accepts connections and keeps the frames
// written to them, so a test can read what went over the wire.
type syslogSink struct {
	host string
	port int

	mu  sync.Mutex
	got []string
}

func newSyslogSink(t *testing.T) *syslogSink {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	addr := ln.Addr().(*net.TCPAddr)
	s := &syslogSink{host: "127.0.0.1", port: addr.Port}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				b, _ := io.ReadAll(conn)
				s.mu.Lock()
				defer s.mu.Unlock()
				s.got = append(s.got, parseFrames(b)...)
			}()
		}
	}()
	return s
}

// frames waits for the collector to have seen n of them. The write and the
// read are on different goroutines, so this polls rather than assuming.
func (s *syslogSink) frames(t *testing.T, n int) []string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		s.mu.Lock()
		got := append([]string(nil), s.got...)
		s.mu.Unlock()
		if len(got) >= n {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("the collector saw %d frames, want %d", len(got), n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// parseFrames splits an octet-counted stream back into messages. It is the
// receiver's half of RFC 6587, written out so the test reads the wire the
// way a collector does.
func parseFrames(b []byte) []string {
	var out []string
	for len(b) > 0 {
		sp := bytes.IndexByte(b, ' ')
		if sp <= 0 {
			return out
		}
		n, err := strconv.Atoi(string(b[:sp]))
		if err != nil || sp+1+n > len(b) {
			return out
		}
		out = append(out, string(b[sp+1:sp+1+n]))
		b = b[sp+1+n:]
	}
	return out
}

func splitLines(b []byte) []string {
	var out []string
	for _, line := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}
