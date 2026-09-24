package audit

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Where a copy of the trail can go. A SIEM team rarely gets to choose the
// shape of its ingest: the collector is whatever the organisation already
// runs, so the same cursor, the same batching and the same back-off sit
// behind four wire formats rather than one.
const (
	KindWebhook = "webhook"
	KindSyslog  = "syslog"
	KindSplunk  = "splunk"
	KindOTLP    = "otlp"
)

// Kinds lists every destination this build can ship to, in the order the
// API offers them. The `kind` column is constrained to the same set.
var Kinds = []string{KindWebhook, KindSyslog, KindSplunk, KindOTLP}

// Syslog message payloads.
const (
	FormatRFC5424 = "rfc5424"
	FormatCEF     = "cef"
)

// syslogSecurity is the default facility: these are authentication and
// authorisation records, which is what facility 10 is for.
const syslogSecurity = 10

const (
	exportUserAgent = "supermcp-audit-exporter"
	// vendor and product name us in CEF headers and OTLP attributes. They
	// are fixed strings because a receiver writes rules against them.
	vendor  = "supermcp"
	product = "supermcp-audit"
)

// Endpoint is an exporter's sealed configuration. One struct covers every
// kind: the row's `kind` column decides which fields are read, and the
// whole thing is sealed, so a field that holds a credential for one kind
// costs nothing for the others.
//
// Every field is omitempty so that a sealed configuration carries only
// what its kind uses, and nothing about the other kinds is implied by its
// absence.
type Endpoint struct {
	Kind string `json:"kind,omitempty"`

	// URL is the receiver for a webhook, the collector for Splunk HEC and
	// the logs endpoint for OTLP.
	URL string `json:"url,omitempty"`
	// Secret signs webhook deliveries.
	Secret string `json:"secret,omitempty"`
	// Token is the Splunk HEC token, sent as an Authorization header.
	Token string `json:"token,omitempty"`
	// Index optionally overrides the Splunk index a batch lands in.
	Index string `json:"index,omitempty"`
	// Headers are extra headers for OTLP, which is how a collector behind
	// an authenticating proxy is reached. They may hold a credential, so
	// they are never read back out.
	Headers map[string]string `json:"headers,omitempty"`

	// Host, Port, TLS, Facility and Format configure syslog.
	Host     string `json:"host,omitempty"`
	Port     int    `json:"port,omitempty"`
	TLS      bool   `json:"tls,omitempty"`
	Facility int    `json:"facility,omitempty"`
	Format   string `json:"format,omitempty"`
}

// Normalise fills in the defaults a configuration may leave out, so that
// what is sealed says plainly what the sweep will do rather than relying
// on a zero value being read the same way later.
func (e *Endpoint) Normalise() {
	if e.Kind == "" {
		e.Kind = KindWebhook
	}
	if e.Kind == KindSyslog {
		if e.Format == "" {
			e.Format = FormatRFC5424
		}
		if e.Facility == 0 {
			e.Facility = syslogSecurity
		}
		if e.Port == 0 {
			if e.TLS {
				e.Port = 6514 // RFC 5425
			} else {
				e.Port = 514
			}
		}
	}
}

// Validate reports what is missing or wrong, in terms an administrator can
// act on. It is the one definition of a usable destination: the API checks
// a configuration with it before sealing, and the sweep checks it again
// after opening, because a row may have been written by an older build.
func (e Endpoint) Validate() error {
	switch e.Kind {
	case KindWebhook:
		if err := validateHTTPURL(e.URL); err != nil {
			return err
		}
		if e.Secret == "" {
			return errors.New("a webhook has no signing secret to sign deliveries with")
		}
	case KindSplunk:
		if err := validateHTTPURL(e.URL); err != nil {
			return err
		}
		if e.Token == "" {
			return errors.New("a Splunk collector needs an HEC token")
		}
	case KindOTLP:
		if err := validateHTTPURL(e.URL); err != nil {
			return err
		}
		for k := range e.Headers {
			if strings.TrimSpace(k) == "" || strings.ContainsAny(k, "\r\n") {
				return errors.New("an OTLP header name is empty or contains a line break")
			}
		}
	case KindSyslog:
		if strings.TrimSpace(e.Host) == "" {
			return errors.New("a syslog destination needs a host")
		}
		if e.Port <= 0 || e.Port > 65535 {
			return fmt.Errorf("syslog port %d is not a port", e.Port)
		}
		if e.Facility < 0 || e.Facility > 23 {
			return fmt.Errorf("syslog facility %d is outside 0-23", e.Facility)
		}
		if e.Format != FormatRFC5424 && e.Format != FormatCEF {
			return fmt.Errorf("syslog format %q is not %s or %s", e.Format, FormatRFC5424, FormatCEF)
		}
	default:
		return fmt.Errorf("destination kind %q is not one this build can ship to", e.Kind)
	}
	return nil
}

// validateHTTPURL refuses what the SSRF guard cannot. The guard classifies
// addresses at connect time; the scheme has to be refused here, before a
// customer-supplied URL turns a delivery into a request for something that
// is not HTTP.
func validateHTTPURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("parse destination url: %w", err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return fmt.Errorf("destination url scheme %q is not http or https", u.Scheme)
	}
	if u.Host == "" {
		return errors.New("destination url has no host")
	}
	return nil
}

// Destination describes where deliveries go, for a reader who is allowed
// to see the configuration but not its secrets. A destination nobody can
// see is a destination nobody can check; a password in a URL is a secret
// wherever it happens to be written, so it does not come back out.
func (e Endpoint) Destination() string {
	switch e.Kind {
	case KindSyslog:
		scheme := "syslog"
		if e.TLS {
			scheme = "syslog+tls"
		}
		return scheme + "://" + net.JoinHostPort(e.Host, strconv.Itoa(e.Port))
	default:
		u, err := url.Parse(e.URL)
		if err != nil {
			return ""
		}
		return u.Redacted()
	}
}

// Deliveries says how a receiver will be handed the trail, so whoever set
// the destination up knows what to configure at the other end.
func (e Endpoint) Deliveries() string {
	switch e.Kind {
	case KindSyslog:
		return fmt.Sprintf("RFC 5424 over TCP with octet counting, %s payload, facility %d", e.Format, e.Facility)
	case KindSplunk:
		return "POST to the HEC collector, one event per line, Authorization: Splunk"
	case KindOTLP:
		return "OTLP/HTTP JSON log records POSTed to the logs endpoint"
	default:
		return "POST, signed with HMAC-SHA256 in " + SignatureHeader
	}
}

// --- shipping ---

// destination ships one batch somewhere. Everything around it — which
// events, in what order, how far the cursor has got and how long to wait
// after a refusal — is the same whatever the kind, and lives in the sweep.
type destination interface {
	// Send returns nil only when the receiver has taken every record in
	// the batch, because the cursor moves on nil.
	Send(ctx context.Context, records []Record) error
}

// DialFunc opens a connection. The sweep is given the SSRF-guarded dialer,
// for the same reason the HTTP destinations are given the guarded client:
// a syslog host is customer-supplied and must not be able to reach inside
// the network.
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// newDestination builds the shipper for one exporter row. The kind comes
// from the column rather than the sealed blob, so a row cannot quietly
// change what it is by being re-sealed.
func newDestination(kind string, ep Endpoint, orgID string, client Doer, dial DialFunc) (destination, error) {
	ep.Kind = kind
	ep.Normalise()
	if err := ep.Validate(); err != nil {
		return nil, err
	}
	if client == nil && kind != KindSyslog {
		return nil, errors.New("this destination speaks HTTP, and no outbound client is configured")
	}
	switch kind {
	case KindWebhook:
		return &webhookDest{ep: ep, client: client}, nil
	case KindSplunk:
		return &splunkDest{ep: ep, client: client, host: localHost()}, nil
	case KindOTLP:
		return &otlpDest{ep: ep, client: client, orgID: orgID}, nil
	case KindSyslog:
		if dial == nil {
			// Dialling unguarded is not a fallback: it is the thing the
			// guard exists to stop.
			return nil, errors.New("syslog destinations need a guarded dialer, and none is configured")
		}
		return &syslogDest{ep: ep, dial: dial, host: localHost()}, nil
	}
	return nil, fmt.Errorf("destination kind %q is not one this build can ship to", kind)
}

// --- webhook ---

type webhookDest struct {
	ep     Endpoint
	client Doer
}

func (w *webhookDest) Send(ctx context.Context, records []Record) error {
	body, err := ndjson(records)
	if err != nil {
		return err
	}
	ts := time.Now().Unix()
	return post(ctx, w.client, w.ep.URL, "application/x-ndjson", body, func(h http.Header) {
		h.Set(TimestampHeader, strconv.FormatInt(ts, 10))
		h.Set(SignatureHeader, SignDelivery(w.ep.Secret, ts, body))
	})
}

// --- Splunk HEC ---

type splunkDest struct {
	ep     Endpoint
	client Doer
	host   string
}

// splunkEvent is one HEC envelope. The collector reads the metadata and
// indexes what is under "event", which is the record as the read API
// returns it, so a Splunk search and the audit explorer show the same
// fields under the same names.
type splunkEvent struct {
	Time       float64 `json:"time"`
	Host       string  `json:"host,omitempty"`
	Source     string  `json:"source"`
	SourceType string  `json:"sourcetype"`
	Index      string  `json:"index,omitempty"`
	Event      *Record `json:"event"`
}

func (s *splunkDest) Send(ctx context.Context, records []Record) error {
	var buf bytes.Buffer
	buf.Grow(len(records) * 640)
	enc := json.NewEncoder(&buf)
	for i := range records {
		// HEC takes epoch seconds with a fractional part; the event's own
		// time is used rather than now, or a replayed backlog would all
		// land at the moment it was delivered.
		ev := splunkEvent{
			Time:       float64(records[i].Time.UTC().UnixNano()) / float64(time.Second),
			Host:       s.host,
			Source:     vendor,
			SourceType: "supermcp:audit",
			Index:      s.ep.Index,
			Event:      &records[i],
		}
		if err := enc.Encode(&ev); err != nil {
			return err
		}
	}
	return post(ctx, s.client, s.ep.URL, "application/json", buf.Bytes(), func(h http.Header) {
		h.Set("Authorization", "Splunk "+s.ep.Token)
	})
}

// --- OTLP logs ---

type otlpDest struct {
	ep     Endpoint
	client Doer
	orgID  string
}

// The OTLP/HTTP JSON encoding of a logs request. Only the fields a log
// record needs are modelled: 64-bit numbers travel as strings, which is
// what the protobuf JSON mapping requires and what collectors expect.
type (
	otlpPayload struct {
		ResourceLogs []otlpResourceLogs `json:"resourceLogs"`
	}
	otlpResourceLogs struct {
		Resource  otlpResource    `json:"resource"`
		ScopeLogs []otlpScopeLogs `json:"scopeLogs"`
	}
	otlpResource struct {
		Attributes []otlpAttr `json:"attributes,omitempty"`
	}
	otlpScopeLogs struct {
		Scope      otlpScope    `json:"scope"`
		LogRecords []otlpRecord `json:"logRecords"`
	}
	otlpScope struct {
		Name string `json:"name"`
	}
	otlpRecord struct {
		TimeUnixNano         string     `json:"timeUnixNano"`
		ObservedTimeUnixNano string     `json:"observedTimeUnixNano"`
		SeverityNumber       int        `json:"severityNumber"`
		SeverityText         string     `json:"severityText"`
		Body                 otlpValue  `json:"body"`
		Attributes           []otlpAttr `json:"attributes,omitempty"`
	}
	otlpAttr struct {
		Key   string    `json:"key"`
		Value otlpValue `json:"value"`
	}
	otlpValue struct {
		String *string `json:"stringValue,omitempty"`
		Int    *string `json:"intValue,omitempty"`
	}
)

func otlpString(v string) otlpValue { return otlpValue{String: &v} }

func otlpInt(v int64) otlpValue {
	s := strconv.FormatInt(v, 10)
	return otlpValue{Int: &s}
}

// attr appends an attribute unless the value is empty, so a collector is
// not handed a key that says nothing.
func attr(into []otlpAttr, key, value string) []otlpAttr {
	if value == "" {
		return into
	}
	return append(into, otlpAttr{Key: key, Value: otlpString(value)})
}

func (o *otlpDest) Send(ctx context.Context, records []Record) error {
	logs := make([]otlpRecord, 0, len(records))
	for i := range records {
		r := &records[i]
		nanos := strconv.FormatInt(r.Time.UTC().UnixNano(), 10)
		sev, text := otlpSeverity(r.Outcome)
		as := []otlpAttr{{Key: "audit.seq", Value: otlpInt(r.Seq)}}
		as = attr(as, "audit.id", r.ID)
		as = attr(as, "audit.category", r.Category)
		as = attr(as, "audit.action", r.Action)
		as = attr(as, "audit.outcome", r.Outcome)
		as = attr(as, "audit.hash", r.Hash)
		as = attr(as, "actor.kind", r.ActorKind)
		as = attr(as, "actor.id", r.ActorID)
		as = attr(as, "actor.display", r.ActorDisplay)
		as = attr(as, "target.kind", r.TargetKind)
		as = attr(as, "target.id", r.TargetID)
		as = attr(as, "target.display", r.TargetDisplay)
		as = attr(as, "client.address", r.IP)
		logs = append(logs, otlpRecord{
			TimeUnixNano: nanos, ObservedTimeUnixNano: nanos,
			SeverityNumber: sev, SeverityText: text,
			// The body is the line a human reads in a log viewer; every
			// field it summarises is also an attribute, which is what a
			// query filters on.
			Body:       otlpString(r.Action + " " + r.Outcome),
			Attributes: as,
		})
	}
	res := otlpResource{Attributes: attr([]otlpAttr{{Key: "service.name", Value: otlpString(vendor)}},
		"supermcp.organization", o.orgID)}
	body, err := json.Marshal(otlpPayload{ResourceLogs: []otlpResourceLogs{{
		Resource:  res,
		ScopeLogs: []otlpScopeLogs{{Scope: otlpScope{Name: "supermcp/audit"}, LogRecords: logs}},
	}}})
	if err != nil {
		return err
	}
	return post(ctx, o.client, o.ep.URL, "application/json", body, func(h http.Header) {
		for k, v := range o.ep.Headers {
			h.Set(k, v)
		}
	})
}

// otlpSeverity maps an outcome onto the OTLP severity scale. A denial is a
// warning rather than an error: nothing went wrong, something was stopped.
func otlpSeverity(outcome string) (int, string) {
	switch outcome {
	case Failure:
		return 17, "ERROR"
	case Denied:
		return 13, "WARN"
	default:
		return 9, "INFO"
	}
}

// --- syslog ---

type syslogDest struct {
	ep   Endpoint
	dial DialFunc
	host string
}

// Send writes the whole batch over one connection and closes it. A syslog
// collector is a stream, and holding a stream open between sweeps would
// mean a half-dead connection that the next batch discovers by losing it;
// dialling per batch costs a handshake a minute and never loses a record.
func (s *syslogDest) Send(ctx context.Context, records []Record) error {
	ctx, cancel := context.WithTimeout(ctx, exportTimeout)
	defer cancel()
	raw, err := s.dial(ctx, "tcp", net.JoinHostPort(s.ep.Host, strconv.Itoa(s.ep.Port)))
	if err != nil {
		return err
	}
	conn := raw
	if s.ep.TLS {
		// The collector's certificate is verified against the configured
		// host: a transport that ships the audit trail is exactly where a
		// silent downgrade would be worth the most to an attacker.
		tc := tls.Client(raw, &tls.Config{ServerName: s.ep.Host, MinVersion: tls.VersionTLS12})
		if err := tc.HandshakeContext(ctx); err != nil {
			_ = raw.Close()
			return fmt.Errorf("syslog tls handshake: %w", err)
		}
		conn = tc
	}
	defer func() { _ = conn.Close() }()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetWriteDeadline(deadline)
	}
	var buf bytes.Buffer
	buf.Grow(len(records) * 640)
	for i := range records {
		msg := s.message(&records[i])
		// RFC 6587 octet counting: the length in bytes, a space, then the
		// message. The alternative framing ends a message at a newline,
		// which a CEF extension or a JSON string can contain, so a batch
		// sent that way can arrive as a different number of events than
		// was sent.
		buf.WriteString(strconv.Itoa(len(msg)))
		buf.WriteByte(' ')
		buf.WriteString(msg)
	}
	if _, err := conn.Write(buf.Bytes()); err != nil {
		return err
	}
	return nil
}

// message renders one record as an RFC 5424 message. The payload after the
// header is either the record as JSON or a CEF line, which is what a SIEM
// that speaks ArcSight's dialect expects to parse.
func (s *syslogDest) message(r *Record) string {
	pri := s.ep.Facility*8 + syslogSeverity(r.Outcome)
	payload := ""
	if s.ep.Format == FormatCEF {
		payload = cefLine(r)
	} else {
		b, err := json.Marshal(r)
		if err != nil {
			// A record that will not marshal must still be recorded as
			// having happened, so the line degrades rather than vanishes.
			payload = fmt.Sprintf(`{"seq":%d,"error":"this event could not be encoded"}`, r.Seq)
		} else {
			payload = string(b)
		}
	}
	// VERSION is 1, PROCID is not meaningful across replicas and is left
	// nil, and the structured data element is nil because everything a
	// receiver needs is in the payload. No BOM precedes the message: a CEF
	// receiver expects the line to start at "CEF:" and a JSON one at "{".
	return fmt.Sprintf("<%d>1 %s %s %s - %s - %s",
		pri,
		r.Time.UTC().Format("2006-01-02T15:04:05.000000Z07:00"),
		printable(s.host, 255),
		printable(product, 48),
		printable(r.Action, 32),
		payload)
}

// syslogSeverity maps an outcome onto the syslog scale: informational for
// what worked, warning for what was refused by policy, error for what
// failed.
func syslogSeverity(outcome string) int {
	switch outcome {
	case Failure:
		return 3
	case Denied:
		return 4
	default:
		return 6
	}
}

// printable keeps a header field inside what RFC 5424 allows: printable
// US-ASCII without spaces, bounded in length, and "-" when there is
// nothing to say.
func printable(s string, max int) string {
	var b strings.Builder
	for _, r := range s {
		if r < '!' || r > '~' {
			r = '_'
		}
		b.WriteRune(r)
		if b.Len() >= max {
			break
		}
	}
	if b.Len() == 0 {
		return "-"
	}
	return b.String()
}

// cefLine renders a record as CEF:0. The header fields are pipe-separated
// and the extension is space-separated key=value, each with its own
// escaping rules, which is why the two are escaped by different helpers.
func cefLine(r *Record) string {
	var b strings.Builder
	b.WriteString("CEF:0|")
	b.WriteString(cefHeader(vendor))
	b.WriteString("|")
	b.WriteString(cefHeader(product))
	b.WriteString("|1|")
	b.WriteString(cefHeader(r.Action))
	b.WriteString("|")
	b.WriteString(cefHeader(r.Action + " " + r.Outcome))
	b.WriteString("|")
	b.WriteString(strconv.Itoa(cefSeverity(r.Outcome)))
	b.WriteString("|")
	ext := func(key, value string) {
		if value == "" {
			return
		}
		b.WriteString(key)
		b.WriteString("=")
		b.WriteString(cefValue(value))
		b.WriteString(" ")
	}
	// rt is the CEF field for when the event happened, in milliseconds.
	ext("rt", strconv.FormatInt(r.Time.UTC().UnixMilli(), 10))
	ext("externalId", r.ID)
	ext("cat", r.Category)
	ext("act", r.Action)
	ext("outcome", r.Outcome)
	ext("suid", r.ActorID)
	ext("suser", r.ActorDisplay)
	ext("src", r.IP)
	ext("cs1Label", "targetKind")
	ext("cs1", r.TargetKind)
	ext("cs2Label", "targetId")
	ext("cs2", r.TargetID)
	ext("cs3Label", "hash")
	ext("cs3", r.Hash)
	ext("cn1Label", "seq")
	ext("cn1", strconv.FormatInt(r.Seq, 10))
	return strings.TrimRight(b.String(), " ")
}

// cefSeverity is CEF's own 0-10 scale, which is not syslog's.
func cefSeverity(outcome string) int {
	switch outcome {
	case Failure:
		return 6
	case Denied:
		return 8
	default:
		return 3
	}
}

var (
	cefHeaderEscape = strings.NewReplacer(`\`, `\\`, `|`, `\|`, "\n", " ", "\r", " ")
	cefValueEscape  = strings.NewReplacer(`\`, `\\`, `=`, `\=`, "\n", `\n`, "\r", `\r`)
)

func cefHeader(s string) string { return cefHeaderEscape.Replace(s) }
func cefValue(s string) string  { return cefValueEscape.Replace(s) }

// --- shared HTTP delivery ---

// post sends one body and reports whether the receiver took it. Every
// destination that speaks HTTP shares it: the status rule, the bounded
// read of a rejection and the drain of an acceptance are the same wherever
// the batch is going.
func post(ctx context.Context, client Doer, endpoint, contentType string, body []byte, headers func(http.Header)) error {
	ctx, cancel := context.WithTimeout(ctx, exportTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", exportUserAgent)
	if headers != nil {
		headers(req.Header)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 == 2 {
		// Drain a little so the connection can be reused; what a receiver
		// says about a batch it accepted is not ours to act on.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, exportErrorMax))
		return nil
	}
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, exportErrorMax))
	return fmt.Errorf("receiver returned %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
}

// localHost is what this replica calls itself, for the syslog HOSTNAME
// field and the Splunk host field. It is read once: a receiver grouping by
// host wants a stable value, and it cannot change under a running process.
func localHost() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "-"
	}
	return h
}
