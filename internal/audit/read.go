package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/supermcpco/supermcp/internal/tenant"
)

// Record is an event as read back.
type Record struct {
	Seq           int64          `json:"seq"`
	ID            string         `json:"id"`
	Time          time.Time      `json:"time"`
	Category      string         `json:"category"`
	Action        string         `json:"action"`
	Outcome       string         `json:"outcome"`
	ActorKind     string         `json:"actorKind"`
	ActorID       string         `json:"actorId,omitempty"`
	ActorDisplay  string         `json:"actorDisplay,omitempty"`
	TargetKind    string         `json:"targetKind,omitempty"`
	TargetID      string         `json:"targetId,omitempty"`
	TargetDisplay string         `json:"targetDisplay,omitempty"`
	IP            string         `json:"ip,omitempty"`
	Diff          map[string]any `json:"diff,omitempty"`
	Payload       any            `json:"payload,omitempty"`
	Meta          map[string]any `json:"meta,omitempty"`
	Hash          string         `json:"hash"`
}

// Query filters a read.
type Query struct {
	OrgID    string
	Category string
	Action   string
	ActorID  string
	TargetID string
	Outcome  string
	// Search is free text in websearch syntax (websearch_to_tsquery):
	// words, "quoted phrases", or, and -excluded. Blank means no search.
	// Text that holds no word at all, such as "!!!", matches nothing.
	Search   string
	From     *time.Time
	To       *time.Time
	AfterSeq int64
	Limit    int
}

// Reader reads the stream.
type Reader struct {
	DB *tenant.DB
	// VerifyAnchor checks a checkpoint anchor's signature over the chain
	// hash it records. Nil checks the anchors' hashes against the chain
	// but not who signed them.
	VerifyAnchor func(ctx context.Context, hash []byte, signature string) error
}

const listColumns = `SELECT seq, id, ts, category, action, outcome, actor_kind, COALESCE(actor_id,''), actor_display,
	COALESCE(target_kind,''), COALESCE(target_id,''), target_display, host(ip), diff, payload, meta, hash
	FROM audit_events`

// listSQL is a page of the list without a search.
const listSQL = listColumns + `
	WHERE organization_id = $1
	  AND ($2 = '' OR category = $2)
	  AND ($3 = '' OR action = $3)
	  AND ($4 = '' OR actor_id = $4)
	  AND ($5 = '' OR target_id = $5)
	  AND ($6 = '' OR outcome = $6)
	  AND ($7::timestamptz IS NULL OR ts >= $7)
	  AND ($8::timestamptz IS NULL OR ts <= $8)
	  AND ($9 = 0 OR seq < $9)
	ORDER BY seq DESC LIMIT $10`

// listSearchSQL is a page of the list with a search. audit_search
// (migration 00027) finds the page's sequence numbers, applying the search
// and every other filter; this reads those events. The search cannot be a
// condition here: under the table's row-level security the text match may
// not use its index, and a search would read every event the workspace
// has. The function is SECURITY DEFINER and takes the workspace from the
// transaction's own setting, and the policy still applies to this read.
const listSearchSQL = listColumns + `
	WHERE organization_id = $1
	  AND seq = ANY(ARRAY(SELECT audit_search($2, $3, $4, $5, $6, $7, $8, $9, $10, $11)))
	ORDER BY seq DESC`

// listTimeout bounds one page of the list, the search included.
const listTimeout = 10 * time.Second

// ErrTimeout is returned when a page of the list took longer than it may.
// A search for common words over a long time range is what usually does
// it; narrowing either helps.
var ErrTimeout = errors.New("the audit query took too long")

// List returns matching events, newest first.
func (r *Reader) List(ctx context.Context, q Query) ([]Record, error) {
	if q.Limit <= 0 || q.Limit > 500 {
		q.Limit = 100
	}
	sql := listSQL
	args := []any{q.OrgID, q.Category, q.Action, q.ActorID, q.TargetID, q.Outcome, q.From, q.To, q.AfterSeq, q.Limit}
	if search := strings.TrimSpace(q.Search); search != "" {
		sql = listSearchSQL
		args = []any{q.OrgID, search, q.Category, q.Action, q.ActorID, q.TargetID, q.Outcome, q.From, q.To, q.AfterSeq, q.Limit}
	}
	ctx, cancel := context.WithTimeout(ctx, listTimeout)
	defer cancel()
	out := []Record{}
	err := r.DB.Tx(tenant.WithOrg(ctx, q.OrgID), func(tx pgx.Tx) error {
		// The context deadline stops this side; the statement timeout makes
		// Postgres stop too, rather than finish a search nobody will read.
		if _, err := tx.Exec(ctx, `SELECT set_config('statement_timeout', $1, true)`,
			strconv.FormatInt(listTimeout.Milliseconds(), 10)); err != nil {
			return fmt.Errorf("audit list: statement timeout: %w", err)
		}
		rows, err := tx.Query(ctx, sql, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var rec Record
			var id uuid.UUID
			var ip *string
			var diff, payload, meta []byte
			var hash []byte
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
	// 57014 is query_canceled, which is what statement_timeout raises.
	var pgErr *pgconn.PgError
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &pgErr) && pgErr.Code == "57014") {
		return nil, fmt.Errorf("%w: %w", ErrTimeout, err)
	}
	return out, err
}

// SeqRange reports the first and last sequence an organisation holds, so a
// caller can verify the stretch of chain its own events live in. Both are
// zero when the organisation has never written an event.
func (r *Reader) SeqRange(ctx context.Context, orgID string) (int64, int64, error) {
	var first, last int64
	err := r.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT COALESCE(MIN(seq),0), COALESCE(MAX(seq),0)
			FROM audit_events WHERE organization_id = $1`, orgID).Scan(&first, &last)
	})
	if err != nil {
		return 0, 0, err
	}
	return first, last, nil
}

// VerifyResult reports on the chain.
type VerifyResult struct {
	Checked   int64  `json:"checked"`
	FirstSeq  int64  `json:"firstSeq"`
	LastSeq   int64  `json:"lastSeq"`
	Valid     bool   `json:"valid"`
	BrokenAt  int64  `json:"brokenAt,omitempty"`
	Explained string `json:"explanation,omitempty"`
	// Scrubbed counts rows whose content was lawfully removed. Their place
	// in the chain is still proved; what they contained is not, and saying
	// so is more honest than a bare "valid".
	Scrubbed int64 `json:"scrubbed,omitempty"`
	// Anchors counts the signed checkpoints the walk met and matched.
	Anchors int64 `json:"anchors"`
	// Unsigned counts checkpoints written without a signing key. Their
	// hash still has to match; who wrote them cannot be proved.
	Unsigned int64 `json:"unsigned,omitempty"`
	// RetentionCut is the last sequence a retention cut removed, when the
	// walk starts right after it; zero when it starts at the beginning of
	// the stream or part-way along. Rows the cut deleted one by one and
	// rows it dropped with their monthly partition are the same cut.
	RetentionCut int64 `json:"retentionCut,omitempty"`
}

type checkpoint struct {
	hash      []byte
	signature string
}

// Verify walks the chain and reports the first row that does not follow
// from its predecessor.
//
// Two things are checked per row. The links: each row records the hash of
// the one before it, and its own hash is recomputed from its facts and the
// digest of its content. And the content: where content is still present,
// its digest must match the one the chain covers, which is what catches an
// edit to a payload or a diff. A row whose content was scrubbed keeps its
// digest and its place in the chain, and is counted rather than failed.
//
// Rows removed by retention are expected, and are bridged by a
// retention_cut anchor recording what the last removed row hashed to. A
// month retention dropped as a partition is part of the same cut and is
// bridged by the same anchor; a partition dropped any other way is a gap
// like any other deletion.
//
// The links alone cannot catch someone with write access who rewrites the
// chain from some row onward and recomputes every hash after it, nor one
// who deletes the newest rows. The signed checkpoints can: each records
// the hash its row had when it was written, so a rewritten row no longer
// matches its checkpoint, a checkpoint edited to match no longer carries a
// valid signature, and a checkpoint past the last row means rows were
// removed from the head.
func (r *Reader) Verify(ctx context.Context, fromSeq, toSeq int64) (*VerifyResult, error) {
	res := &VerifyResult{Valid: true}
	err := r.DB.Bypass(ctx, "audit-verify", func(tx pgx.Tx) error {
		cuts := map[int64][]byte{}
		crows, err := tx.Query(ctx, `SELECT seq, hash FROM audit_anchors WHERE kind = 'retention_cut'`)
		if err != nil {
			return err
		}
		for crows.Next() {
			var seq int64
			var h []byte
			if err := crows.Scan(&seq, &h); err != nil {
				crows.Close()
				return err
			}
			cuts[seq] = h
		}
		crows.Close()

		checkpoints := map[int64]checkpoint{}
		var lastCheckpoint int64
		arows, err := tx.Query(ctx, `SELECT seq, hash, COALESCE(signature,'') FROM audit_anchors
			WHERE kind = 'checkpoint' AND ($1 = 0 OR seq >= $1) AND ($2 = 0 OR seq <= $2)`, fromSeq, toSeq)
		if err != nil {
			return err
		}
		for arows.Next() {
			var seq int64
			var c checkpoint
			if err := arows.Scan(&seq, &c.hash, &c.signature); err != nil {
				arows.Close()
				return err
			}
			checkpoints[seq] = c
			lastCheckpoint = max(lastCheckpoint, seq)
		}
		arows.Close()
		if err := arows.Err(); err != nil {
			return err
		}

		rows, err := tx.Query(ctx, `SELECT seq, id, ts, organization_id, category, action, outcome, actor_kind, actor_id,
			target_kind, target_id, diff, payload, meta, content_hash, prev_hash, hash, scrubbed_at IS NOT NULL
			FROM audit_events WHERE ($1 = 0 OR seq >= $1) AND ($2 = 0 OR seq <= $2) ORDER BY seq`, fromSeq, toSeq)
		if err != nil {
			return err
		}
		defer rows.Close()
		var prev []byte
		first := true
		for rows.Next() {
			var seq int64
			var id uuid.UUID
			var org, actorID, targetKind, targetID *string
			var rec row
			var diff, payload, meta, contentHash, prevHash, hash []byte
			var scrubbed bool
			if err := rows.Scan(&seq, &id, &rec.ts, &org, &rec.category, &rec.action, &rec.outcome, &rec.actorKind,
				&actorID, &targetKind, &targetID, &diff, &payload, &meta, &contentHash, &prevHash, &hash, &scrubbed); err != nil {
				return err
			}
			rec.id, rec.diff, rec.payload, rec.meta = id, diff, payload, meta
			rec.contentHash = contentHash
			rec.orgID, rec.actorID = deref(org), deref(actorID)
			rec.targetKind, rec.targetID = deref(targetKind), deref(targetID)

			if first {
				// What came before the first row has to be accounted for,
				// or deleting the oldest rows is undetectable: the row that
				// becomes the first simply claims a predecessor nobody can
				// check. Either it is the genesis row, or a retention cut
				// anchor records what the removed predecessor hashed to.
				h, ok := cuts[seq-1]
				switch {
				case ok && !bytes.Equal(h, prevHash):
					res.Valid, res.BrokenAt = false, seq
					res.Explained = fmt.Sprintf("row %d does not follow the retention cut recorded before it", seq)
					return nil
				case !ok && fromSeq == 0 && !bytes.Equal(prevHash, make([]byte, sha256.Size)):
					res.Valid, res.BrokenAt = false, seq
					res.Explained = fmt.Sprintf(
						"the stream starts at row %d, which follows a row that is not there and no retention cut explains", seq)
					return nil
				}
				if ok {
					res.RetentionCut = seq - 1
				}
				prev = prevHash
				res.FirstSeq = seq
				first = false
			}
			if !bytes.Equal(prevHash, prev) {
				res.Valid, res.BrokenAt = false, seq
				res.Explained = fmt.Sprintf("row %d records a different predecessor than row %d", seq, res.LastSeq)
				if res.LastSeq < seq-1 {
					// Sequence numbers can skip (a refused append uses some
					// up), but the link cannot: whatever row this one
					// followed is gone, one by one or with its partition.
					res.Explained = fmt.Sprintf("row %d does not follow row %d, the one before it in the stream; "+
						"what came between was removed (deleted, or dropped with its partition) without a retention cut", seq, res.LastSeq)
				}
				return nil
			}
			want := chainHash(prevHash, &rec)
			if !bytes.Equal(want, hash) {
				res.Valid, res.BrokenAt = false, seq
				res.Explained = fmt.Sprintf("row %d was modified after it was written", seq)
				return nil
			}
			if scrubbed {
				res.Scrubbed++
			} else if !bytes.Equal(ContentHash(diff, payload, meta), contentHash) {
				res.Valid, res.BrokenAt = false, seq
				res.Explained = fmt.Sprintf("the content of row %d was changed after it was written", seq)
				return nil
			}
			if c, ok := checkpoints[seq]; ok {
				if !bytes.Equal(c.hash, hash) {
					res.Valid, res.BrokenAt = false, seq
					res.Explained = fmt.Sprintf("row %d no longer hashes to what its checkpoint recorded; the chain was rewritten from this row or before it", seq)
					return nil
				}
				switch {
				case r.VerifyAnchor == nil:
				case c.signature == "":
					res.Unsigned++
				default:
					if err := r.VerifyAnchor(ctx, c.hash, c.signature); err != nil {
						res.Valid, res.BrokenAt = false, seq
						res.Explained = fmt.Sprintf("the checkpoint at row %d is not validly signed: %v", seq, err)
						return nil
					}
				}
				res.Anchors++
			}
			prev = hash
			res.LastSeq = seq
			res.Checked++
		}
		if err := rows.Err(); err != nil {
			return err
		}
		// A checkpoint beyond the last row walked vouches for a row that
		// is not there: the head of the stream was deleted.
		if res.Valid && lastCheckpoint > res.LastSeq {
			res.Valid, res.BrokenAt = false, res.LastSeq+1
			res.Explained = fmt.Sprintf("a checkpoint was signed at row %d, but the stream ends at row %d; rows were removed from the head", lastCheckpoint, res.LastSeq)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

// Anchor records a signed checkpoint at the current head.
func (r *Reader) Anchor(ctx context.Context, sign func([]byte) (string, error)) error {
	return r.DB.Bypass(ctx, "audit-anchor", func(tx pgx.Tx) error {
		var seq int64
		var hash []byte
		err := tx.QueryRow(ctx, `SELECT seq, hash FROM audit_events ORDER BY seq DESC LIMIT 1`).Scan(&seq, &hash)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		// An anchor at this head already exists on every tick after the
		// first, and signing is a key operation that may be billed and may
		// cross a network, so the check comes before the signature.
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT true FROM audit_anchors WHERE seq = $1`, seq).Scan(&exists); err == nil {
			return nil
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		sig := ""
		if sign != nil {
			if sig, err = sign(hash); err != nil {
				return err
			}
		}
		_, err = tx.Exec(ctx, `INSERT INTO audit_anchors (seq, hash, kind, signature) VALUES ($1,$2,'checkpoint',NULLIF($3,''))
			ON CONFLICT (seq) DO NOTHING`, seq, hash, sig)
		return err
	})
}

// cutLockTimeout bounds how long a cut that has whole partitions to drop
// waits for audit_events, and so how long appends wait behind it.
const cutLockTimeout = "3s"

// CutResult says what a retention cut removed.
type CutResult struct {
	// Seq is the newest event removed, where the retention_cut anchor
	// sits; zero when nothing was.
	Seq int64
	// Deleted counts the events removed, one by one or with their
	// partition.
	Deleted int64
	// Partitions names the monthly partitions dropped whole.
	Partitions []string
}

// Cut removes everything at or below a sequence number, whatever tenant
// wrote it, and records the anchor that lets Verify bridge the gap.
//
// The cut is contiguous on purpose. Every organisation's events share one
// sequence, so deleting one tenant's rows from the middle would leave a
// hole no anchor can bridge: the row after the hole records a predecessor
// that no longer exists. A tenant whose own window is shorter than the
// instance-wide cut is served by Scrub instead, which removes content and
// leaves the link.
//
// Rows under legal hold are never removed, and a hold below the cut stops
// the cut there rather than skipping the row and tearing the chain.
//
// A month that ended before the cutoff and holds nothing above the cut is
// dropped as a partition rather than deleted row by row
// (audit_events_cut, migration 00033). That needs audit_events to itself
// for a moment; if a reader holds it past cutLockTimeout, the whole cut is
// rolled back and the next sweep tries again.
func (r *Reader) Cut(ctx context.Context, before time.Time) (CutResult, error) {
	var res CutResult
	err := r.DB.Bypass(ctx, "audit-cut", func(tx pgx.Tx) error {
		var cutSeq int64
		var cutHash []byte
		// The cut stops at the first row that must stay, so what is deleted
		// is always a prefix.
		err := tx.QueryRow(ctx, `SELECT seq, hash FROM audit_events
			WHERE ts < $1 AND seq < COALESCE((SELECT min(seq) FROM audit_events WHERE legal_hold), 9223372036854775807)
			ORDER BY seq DESC LIMIT 1`, before).Scan(&cutSeq, &cutHash)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO audit_anchors (seq, hash, kind) VALUES ($1,$2,'retention_cut')
			ON CONFLICT (seq) DO UPDATE SET hash = EXCLUDED.hash`, cutSeq, cutHash); err != nil {
			return err
		}
		err = tx.QueryRow(ctx, `SELECT deleted, dropped FROM audit_events_cut($1, $2, $3, $4)`,
			cutSeq, before, chainLockID, cutLockTimeout).Scan(&res.Deleted, &res.Partitions)
		// 55P03 is lock_not_available, which lock_timeout raises.
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "55P03" {
			return fmt.Errorf("audit_events was busy for %s, so the months past retention could not be dropped; "+
				"nothing was cut and the next sweep tries again: %w", cutLockTimeout, err)
		}
		if err != nil {
			return err
		}
		res.Seq = cutSeq
		return nil
	})
	if err != nil {
		return CutResult{}, err
	}
	return res, nil
}

// Scrub removes the content of one organisation's older events while
// leaving them in the chain. It is what honours a retention window shorter
// than the instance-wide cut, and what a lawful erasure request reaches
// for: the record that something happened survives, the record of what was
// in it does not.
func (r *Reader) Scrub(ctx context.Context, orgID string, before time.Time) (int64, error) {
	var scrubbed int64
	err := r.DB.Bypass(ctx, "audit-scrub", func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE audit_events SET diff = NULL, payload = NULL, scrubbed_at = now()
			WHERE organization_id = $1 AND ts < $2 AND NOT legal_hold AND scrubbed_at IS NULL
			  AND (diff IS NOT NULL OR payload IS NOT NULL)`, orgID, before)
		if err != nil {
			return err
		}
		scrubbed = tag.RowsAffected()
		return nil
	})
	return scrubbed, err
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func decodeInto(b []byte, out *map[string]any) {
	if len(b) == 0 {
		return
	}
	m := map[string]any{}
	if err := jsonUnmarshal(b, &m); err == nil {
		*out = m
	}
}

func decodeAny(b []byte, out *any) {
	if len(b) == 0 {
		return
	}
	var v any
	if err := jsonUnmarshal(b, &v); err == nil {
		*out = v
	}
}

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }
