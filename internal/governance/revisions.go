// Package governance keeps the history of a configuration: what each
// connector, tool and MCP server looked like after every change, who made
// it, and how to put an earlier version back.
package governance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/supermcpco/supermcp/internal/audit"
	"github.com/supermcpco/supermcp/internal/tenant"
)

// Kind names what a revision is about.
type Kind string

// The three kinds a revision can describe.
const (
	KindConnector Kind = "connector"
	KindTool      Kind = "tool"
	KindServer    Kind = "server"
	// KindRole is versioned for the same reason a connector is: somebody
	// needs to see what a role allowed last week.
	KindRole Kind = "role"
)

// What a revision says happened. A rollback is an update: it puts an
// earlier snapshot back through the service that owns the entity, so the
// correction is recorded like any other change and the mistake it
// corrects stays where it is.
const (
	ActionCreate = "create"
	ActionUpdate = "update"
	ActionDelete = "delete"
)

// ErrNotFound is returned for a revision that does not exist, or belongs
// to another organisation.
var ErrNotFound = errors.New("revision not found")

// revisionLockClass namespaces the advisory lock that serialises writers
// to one entity. The two-argument form has its own key space, so it
// cannot collide with the audit chain or the migration lock.
const revisionLockClass int32 = 0x5245 // "RE"

// Revision is one recorded change.
//
// Entity is the write side: the object as it stands after the change,
// which Record turns into the stored snapshot. Snapshot is the read side:
// the bytes as they were stored, handed back unchanged so that the
// snapshot a caller sees is the one that was taken.
type Revision struct {
	ID           string          `json:"id"`
	Kind         Kind            `json:"kind"`
	EntityID     string          `json:"entityId"`
	Number       int             `json:"revision"`
	Action       string          `json:"action"`
	Entity       any             `json:"-"`
	Snapshot     json.RawMessage `json:"snapshot,omitempty"`
	Diff         *audit.Diff     `json:"diff,omitempty"`
	ActorID      string          `json:"actorId,omitempty"`
	ActorDisplay string          `json:"actorDisplay,omitempty"`
	CreatedAt    time.Time       `json:"createdAt"`
}

// Service reads and writes the history.
type Service struct {
	DB    *tenant.DB
	NewID func() string
}

// New builds the service.
func New(db *tenant.DB, newID func() string) *Service {
	return &Service{DB: db, NewID: newID}
}

// Record writes a revision inside the caller's transaction, which is the
// only way it is worth writing: the history and the change it describes
// commit together or not at all.
//
// It takes the organisation from the transaction rather than from the
// caller, so a revision cannot land in a tenant other than the one whose
// row was just written. Call it as the last statement of the transaction:
// the snapshot should be of the entity as it ends up, and taking the
// entity's own row lock first keeps the lock order the same everywhere.
// Record satisfies the narrow interface the connector and server services
// depend on, so those packages need no knowledge of this one beyond the
// call itself.
func (s *Service) Record(ctx context.Context, tx pgx.Tx, kind, entityID, action string, entity any, diff *audit.Diff, actorID string) error {
	return s.RecordRevision(ctx, tx, Revision{Kind: Kind(kind), EntityID: entityID, Action: action,
		Entity: entity, Diff: diff, ActorID: actorID})
}

// RecordRevision writes one revision inside the caller's transaction.
func (s *Service) RecordRevision(ctx context.Context, tx pgx.Tx, r Revision) error {
	if r.EntityID == "" {
		return errors.New("a revision needs the id of the entity it describes")
	}
	if !validKind(r.Kind) {
		return fmt.Errorf("unknown entity kind %q", r.Kind)
	}
	if !validAction(r.Action) {
		return fmt.Errorf("unknown revision action %q", r.Action)
	}
	snapshot, err := snapshotOf(r.Entity)
	if err != nil {
		return err
	}
	var diff []byte
	if r.Diff != nil {
		if diff, err = json.Marshal(r.Diff); err != nil {
			return fmt.Errorf("encode revision diff: %w", err)
		}
	}
	// The number is read and written under a lock on the entity, so two
	// writers queue instead of both deciding they are the fourth revision.
	// The unique index is the backstop if they ever manage it anyway.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1, hashtext(current_org() || '/' || $2 || '/' || $3))`,
		revisionLockClass, string(r.Kind), r.EntityID); err != nil {
		return fmt.Errorf("lock revision sequence: %w", err)
	}
	_, err = tx.Exec(ctx, `INSERT INTO revisions
		(id, organization_id, entity_kind, entity_id, revision, snapshot, diff, action, actor_id, actor_display)
		SELECT $1, current_org(), $2, $3, COALESCE(MAX(revision), 0) + 1, $4, $5, $6, NULLIF($7,''), $8
		FROM revisions WHERE organization_id = current_org() AND entity_kind = $2 AND entity_id = $3`,
		s.NewID(), string(r.Kind), r.EntityID, snapshot, diff, r.Action, r.ActorID, r.ActorDisplay)
	if err != nil {
		return fmt.Errorf("record revision: %w", err)
	}
	return nil
}

// List returns an entity's revisions, newest first. before continues below
// a revision number from an earlier page, and is zero for the first one.
//
// The snapshots are left out: a page of them is a large download of
// something nobody has asked to see yet. Get reads one.
func (s *Service) List(ctx context.Context, orgID string, kind Kind, entityID string, before, limit int) ([]Revision, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	out := []Revision{}
	err := s.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id, entity_kind, entity_id, revision, action, COALESCE(actor_id,''),
			actor_display, created_at, diff FROM revisions
			WHERE entity_kind = $1 AND entity_id = $2 AND ($3 = 0 OR revision < $3)
			ORDER BY revision DESC LIMIT $4`, string(kind), entityID, before, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			r, err := scan(rows, nil)
			if err != nil {
				return err
			}
			out = append(out, *r)
		}
		return rows.Err()
	})
	return out, err
}

// Get reads one revision, with the snapshot exactly as it was stored.
func (s *Service) Get(ctx context.Context, orgID string, kind Kind, entityID string, revision int) (*Revision, error) {
	var r *Revision
	err := s.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		var snapshot []byte
		var err error
		r, err = scan(tx.QueryRow(ctx, `SELECT id, entity_kind, entity_id, revision, action, COALESCE(actor_id,''),
			actor_display, created_at, diff, snapshot FROM revisions
			WHERE entity_kind = $1 AND entity_id = $2 AND revision = $3`,
			string(kind), entityID, revision), &snapshot)
		if err != nil {
			return err
		}
		r.Snapshot = snapshot
		return nil
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return r, nil
}

// Snapshot reads one revision's snapshot as fields, for a caller that is
// about to put them back through the service that owns the entity.
// Nothing here writes to a connector or a server: restoring is that
// service's job, and doing it any other way would skip its rules and its
// own revision.
func (s *Service) Snapshot(ctx context.Context, orgID string, kind Kind, entityID string, revision int) (map[string]any, error) {
	r, err := s.Get(ctx, orgID, kind, entityID, revision)
	if err != nil {
		return nil, err
	}
	return r.Fields()
}

// Fields decodes the snapshot into the field names the API serves.
func (r Revision) Fields() (map[string]any, error) {
	if len(r.Snapshot) == 0 {
		return map[string]any{}, nil
	}
	m := map[string]any{}
	if err := json.Unmarshal(r.Snapshot, &m); err != nil {
		return nil, fmt.Errorf("decode snapshot of revision %d: %w", r.Number, err)
	}
	return m, nil
}

// scan reads the common columns; snapshot is read only where it is asked
// for, because it is the one column that can be large.
func scan(row pgx.Row, snapshot *[]byte) (*Revision, error) {
	var r Revision
	var kind string
	var diff []byte
	dest := []any{&r.ID, &kind, &r.EntityID, &r.Number, &r.Action, &r.ActorID, &r.ActorDisplay, &r.CreatedAt, &diff}
	if snapshot != nil {
		dest = append(dest, snapshot)
	}
	if err := row.Scan(dest...); err != nil {
		return nil, err
	}
	r.Kind = Kind(kind)
	if len(diff) > 0 {
		var d audit.Diff
		if err := json.Unmarshal(diff, &d); err != nil {
			return nil, fmt.Errorf("decode diff of revision %d: %w", r.Number, err)
		}
		r.Diff = &d
	}
	return &r, nil
}

// snapshotOf renders the entity as it will be stored. The redaction is
// audit's own, deliberately: a field named like a credential becomes the
// same digest here as in the audit diff, so the two records of one change
// agree about what they will not repeat. Connector credentials are sealed
// elsewhere and never appear in the entity at all; what a snapshot keeps
// of them is which names existed.
func snapshotOf(entity any) ([]byte, error) {
	if entity == nil {
		return nil, errors.New("a revision needs the entity it describes")
	}
	d := audit.Created(entity)
	if d == nil {
		return nil, errors.New("a snapshot has to be a JSON object")
	}
	b, err := json.Marshal(d.After)
	if err != nil {
		return nil, fmt.Errorf("encode snapshot: %w", err)
	}
	return b, nil
}

func validKind(k Kind) bool {
	return k == KindConnector || k == KindTool || k == KindServer || k == KindRole
}

func validAction(a string) bool {
	return a == ActionCreate || a == ActionUpdate || a == ActionDelete
}
