package audit

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/supermcpco/supermcp/internal/secrets"
	"github.com/supermcpco/supermcp/internal/tenant"
)

// Headers on every delivery. A receiver needs both: the signature alone
// says the body came from us, and says nothing about when.
const (
	SignatureHeader = "X-Supermcp-Signature"
	TimestampHeader = "X-Supermcp-Timestamp"
)

const (
	// exportBatch is how many events go in one delivery.
	exportBatch = 500
	// exportMaxBatches stops one busy organisation from holding the sweep
	// for the whole stream; the rest arrives on the next pass.
	exportMaxBatches = 20
	// exportTimeout caps a single delivery.
	exportTimeout = 30 * time.Second
	// exportFailureThreshold is how many consecutive failures turn an
	// exporter from "try every sweep" into "try on a timer".
	exportFailureThreshold = 3
	exportBackoffBase      = time.Minute
	exportBackoffMax       = 30 * time.Minute
	// exportErrorMax caps what of a rejection is kept in last_error.
	exportErrorMax = 512
)

// Doer sends one request. It is an interface so the sweep can be given the
// SSRF-guarded client (*httpclient.Client) in production and a stub in
// tests; an exporter URL is customer-supplied, so the guarded dialer is
// what keeps a delivery from reaching inside the network.
type Doer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Exporters ships new events to the endpoints organisations have
// configured, at-least-once and resumably.
type Exporters struct {
	DB     *tenant.DB
	Sealer *secrets.Sealer
	HTTP   Doer
	// Dial is the guarded dialer the syslog destinations connect with.
	// Without it a syslog row is reported as misconfigured rather than
	// dialled unguarded.
	Dial DialFunc
	Log  *slog.Logger

	// mu guards retryAt, which outlives a single sweep.
	mu      sync.Mutex
	retryAt map[string]time.Time
}

// NewExporters builds the sweep.
func NewExporters(db *tenant.DB, sealer *secrets.Sealer, client Doer, log *slog.Logger) *Exporters {
	return &Exporters{DB: db, Sealer: sealer, HTTP: client, Log: log, retryAt: map[string]time.Time{}}
}

// WithDial installs the dialer syslog destinations use. It returns the
// receiver so the sweep can be assembled in one expression.
func (e *Exporters) WithDial(dial DialFunc) *Exporters {
	e.Dial = dial
	return e
}

// Run ships everything new to each enabled exporter. One endpoint's
// failure does not stop the others: the errors are joined and reported
// together. Nothing is ever disabled here — an endpoint that has been down
// all weekend is still the operator's to switch off.
func (e *Exporters) Run(ctx context.Context) error {
	// An instance assembled without a database, or with no way out of the
	// process at all, cannot export, which is a configuration state and not
	// an error. A row whose own kind has no transport is reported against
	// that row rather than silencing every other one.
	if e == nil || e.DB == nil || (e.HTTP == nil && e.Dial == nil) {
		return nil
	}
	rows, err := e.enabled(ctx)
	if err != nil {
		return err
	}
	var errs []error
	for _, row := range rows {
		if ctx.Err() != nil {
			return errors.Join(append(errs, ctx.Err())...)
		}
		if e.blocked(row.id) {
			continue
		}
		if err := e.export(ctx, row); err != nil {
			errs = append(errs, fmt.Errorf("exporter %s: %w", row.id, err))
		}
	}
	return errors.Join(errs...)
}

// SignDelivery returns the value of the signature header for one delivery.
//
// The signed material is the Unix timestamp, a full stop, then the body.
// The timestamp is inside the MAC rather than merely travelling beside it:
// a receiver that rejects a timestamp outside its clock skew has, with
// this construction, also rejected the body, so a delivery captured today
// cannot be replayed next week under a fresh timestamp.
func SignDelivery(secret string, unixSeconds int64, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(strconv.FormatInt(unixSeconds, 10)))
	mac.Write([]byte("."))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// --- delivery ---

// source supplies an exporter's unsent events and records how far it has
// got. The sweep backs it with the database; a test backs it with a slice.
type source interface {
	After(ctx context.Context, afterSeq int64, limit int) ([]Record, error)
	Commit(ctx context.Context, seq int64) error
}

// delivery is the part of shipping that does not depend on where the
// events are going: batch, send, move the cursor, stop at the bound.
type delivery struct {
	dest destination
}

// ship sends everything after cursor in batches, moving the cursor only
// once the receiver has accepted one. Delivery is therefore at-least-once:
// a crash between the send and the commit repeats a batch rather than
// losing it, and a receiver is expected to deduplicate on the event id.
func (d *delivery) ship(ctx context.Context, cursor int64, src source) error {
	for i := 0; i < exportMaxBatches; i++ {
		records, err := src.After(ctx, cursor, exportBatch)
		if err != nil {
			return err
		}
		if len(records) == 0 {
			return nil
		}
		if err := d.dest.Send(ctx, records); err != nil {
			return err
		}
		cursor = records[len(records)-1].Seq
		if err := src.Commit(ctx, cursor); err != nil {
			return err
		}
		if len(records) < exportBatch {
			return nil
		}
	}
	return nil
}

// ndjson encodes a batch as newline-delimited JSON so a receiver can
// process it record by record instead of holding the batch in memory.
func ndjson(records []Record) ([]byte, error) {
	var buf bytes.Buffer
	buf.Grow(len(records) * 512)
	enc := json.NewEncoder(&buf)
	for i := range records {
		if err := enc.Encode(&records[i]); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

// --- the sweep ---

type exporterRow struct {
	id         string
	orgID      string
	kind       string
	config     []byte
	categories []string
	cursorSeq  int64
	failures   int
}

func (e *Exporters) export(ctx context.Context, row exporterRow) error {
	ep, err := e.endpoint(ctx, row)
	if err != nil {
		return e.recordFailure(ctx, row, err)
	}
	dest, err := newDestination(row.kind, ep, row.orgID, e.HTTP, e.Dial)
	if err != nil {
		return e.recordFailure(ctx, row, err)
	}
	d := &delivery{dest: dest}
	if err := d.ship(ctx, row.cursorSeq, &dbSource{e: e, row: row}); err != nil {
		return e.recordFailure(ctx, row, err)
	}
	e.clearBackoff(row.id)
	return nil
}

// endpoint opens the sealed configuration. What makes it usable is checked
// where the destination is built, so a row written by an older build, or
// by hand, is refused on the same terms the API refuses a new one.
func (e *Exporters) endpoint(ctx context.Context, row exporterRow) (Endpoint, error) {
	var ep Endpoint
	if e.Sealer == nil {
		return ep, errors.New("no sealer configured")
	}
	pt, err := e.Sealer.Open(ctx, row.config, secrets.AAD{
		Table: "audit_exporters", Column: "config_enc", RowID: row.id, OrgID: row.orgID})
	if err != nil {
		return ep, fmt.Errorf("open exporter configuration: %w", err)
	}
	if err := json.Unmarshal(pt, &ep); err != nil {
		return ep, fmt.Errorf("decode exporter configuration: %w", err)
	}
	return ep, nil
}

func (e *Exporters) enabled(ctx context.Context) ([]exporterRow, error) {
	var out []exporterRow
	err := e.DB.Bypass(ctx, "audit-export", func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id, COALESCE(organization_id,''), kind, config_enc, filter, cursor_seq, consecutive_failures
			FROM audit_exporters WHERE enabled AND kind = ANY($1) ORDER BY id`, Kinds)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r exporterRow
			var filter []byte
			if err := rows.Scan(&r.id, &r.orgID, &r.kind, &r.config, &filter, &r.cursorSeq, &r.failures); err != nil {
				return err
			}
			r.categories = filterCategories(filter)
			out = append(out, r)
		}
		return rows.Err()
	})
	return out, err
}

// filterCategories reads {"categories":["auth","admin"]}. An absent or
// empty list means everything, so a filter nobody filled in does not
// silently stop the stream.
func filterCategories(filter []byte) []string {
	if len(filter) == 0 {
		return nil
	}
	var f struct {
		Categories []string `json:"categories"`
	}
	if err := json.Unmarshal(filter, &f); err != nil || len(f.Categories) == 0 {
		return nil
	}
	return f.Categories
}

func (e *Exporters) recordFailure(ctx context.Context, row exporterRow, cause error) error {
	err := e.DB.Bypass(ctx, "audit-export-failure", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE audit_exporters
			SET consecutive_failures = consecutive_failures + 1, last_error = $2 WHERE id = $1`,
			row.id, truncateError(cause.Error()))
		return err
	})
	e.backOff(row.id, row.failures+1)
	if err != nil {
		return errors.Join(cause, err)
	}
	return cause
}

func truncateError(s string) string {
	if len(s) <= exportErrorMax {
		return s
	}
	return s[:exportErrorMax]
}

// --- back-off ---
//
// The schema counts consecutive failures but does not record when the last
// attempt was, so the retry deadline is held in this process. A restart
// therefore tries a dead endpoint once more, which costs one request and
// avoids a column that two replicas would write over each other.

func (e *Exporters) backOff(id string, failures int) {
	if failures < exportFailureThreshold {
		return
	}
	wait := exportBackoffBase << min(failures-exportFailureThreshold, 8)
	if wait > exportBackoffMax {
		wait = exportBackoffMax
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.retryAt == nil {
		e.retryAt = map[string]time.Time{}
	}
	e.retryAt[id] = time.Now().Add(wait)
	e.logger().Warn("audit exporter backing off", "exporter", id, "failures", failures, "wait", wait)
}

func (e *Exporters) blocked(id string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	at, ok := e.retryAt[id]
	if !ok {
		return false
	}
	if time.Now().Before(at) {
		return true
	}
	delete(e.retryAt, id)
	return false
}

func (e *Exporters) clearBackoff(id string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.retryAt, id)
}

func (e *Exporters) logger() *slog.Logger {
	if e.Log != nil {
		return e.Log
	}
	return slog.Default()
}

// --- the database behind one exporter ---

type dbSource struct {
	e   *Exporters
	row exporterRow
}

func (s *dbSource) After(ctx context.Context, afterSeq int64, limit int) ([]Record, error) {
	out := make([]Record, 0, limit)
	err := s.e.DB.Bypass(ctx, "audit-export-read", func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT seq, id, ts, category, action, outcome, actor_kind, COALESCE(actor_id,''), actor_display,
			COALESCE(target_kind,''), COALESCE(target_id,''), target_display, host(ip), diff, payload, meta, hash
			FROM audit_events
			WHERE organization_id = $1 AND seq > $2
			  AND ($3::text[] IS NULL OR category = ANY($3))
			ORDER BY seq LIMIT $4`, s.row.orgID, afterSeq, s.row.categories, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var rec Record
			var id uuid.UUID
			var ip *string
			var diff, payload, meta, hash []byte
			if err := rows.Scan(&rec.Seq, &id, &rec.Time, &rec.Category, &rec.Action, &rec.Outcome, &rec.ActorKind,
				&rec.ActorID, &rec.ActorDisplay, &rec.TargetKind, &rec.TargetID, &rec.TargetDisplay, &ip,
				&diff, &payload, &meta, &hash); err != nil {
				return err
			}
			rec.ID = id.String()
			if ip != nil {
				rec.IP = *ip
			}
			rec.Hash = hex.EncodeToString(hash)
			decodeInto(diff, &rec.Diff)
			decodeAny(payload, &rec.Payload)
			decodeInto(meta, &rec.Meta)
			out = append(out, rec)
		}
		return rows.Err()
	})
	return out, err
}

// Commit moves the cursor forward only. Two replicas sweeping at the same
// time would otherwise be able to rewind one another and resend a batch
// the receiver has already taken.
func (s *dbSource) Commit(ctx context.Context, seq int64) error {
	return s.e.DB.Bypass(ctx, "audit-export-cursor", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE audit_exporters
			SET cursor_seq = $2, last_ok_at = now(), last_error = NULL, consecutive_failures = 0
			WHERE id = $1 AND cursor_seq < $2`, s.row.id, seq)
		return err
	})
}
