package connector

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"reflect"
	"sort"

	"github.com/jackc/pgx/v5"

	"github.com/supermcpco/supermcp/internal/audit"
	"github.com/supermcpco/supermcp/internal/tenant"
	"github.com/supermcpco/supermcp/pkg/adapter"
)

// Re-sync brings a connector installed from the catalog up to the adapter
// bundled in the running binary. The catalog is compiled in, so a newer
// adapter only ever arrives with an upgrade: the check compares the
// connector's catalog_hash with the bundled adapter's, made when someone
// asks, and nothing runs on a schedule.
//
// Re-sync only moves forward. The generated index keeps each adapter's
// earlier content hashes; a connector is behind only when its hash is one
// of them. A hash this binary does not know may come from a newer one, as
// during a rolling upgrade or after a rollback, and is refused rather than
// overwritten with an older adapter.
//
// Re-sync replaces the instructions and the catalog's tools, never the
// transport or auth: an operator may have pointed the connector at their
// own host, and its sealed credentials would follow the catalog's default
// one. Differences there are reported as settings not applied.
//
// A tool someone changed by hand is never overwritten or deleted. It is
// skipped, and the plan says so:
//   - source 'custom' is a tool made in the editor. The catalog never had
//     it; if the bundled adapter now has a tool of the same name, that one
//     is skipped rather than added.
//   - edited_at set means a person edited the definition; the catalog's
//     version of it is skipped, whether it would update or remove it.
//
// Every other tool on the connector is the catalog's to manage. That
// includes source 'import': migration 00019 notes that a replica older
// than the column labels a catalog install that way, and nothing else
// writes 'import' tools onto a catalog connector. Re-sync relabels them.

// Re-sync errors. The HTTP layer maps each one to a status; see humaErr.
var (
	// ErrNotFromCatalog means the connector was made by hand or from an
	// import, so there is no bundled adapter to compare it with.
	ErrNotFromCatalog = errors.New("this connector was not installed from the catalog, so there is nothing to re-sync it with")
	// ErrNotInCatalog means the bundled catalog no longer has the adapter
	// the connector was installed from.
	ErrNotInCatalog = errors.New("the catalog in this version no longer has the adapter this connector was installed from")
	// ErrCatalogNotBehind means the connector came from a catalog version
	// this binary does not know, which may be a newer one.
	ErrCatalogNotBehind = errors.New("this connector came from a catalog version this server does not know, possibly a newer one; re-sync it from a server that runs that version or a later one")
	// ErrResyncStale means the connector, or the catalog the server runs,
	// changed since the re-sync was reviewed.
	ErrResyncStale = errors.New("the connector or the catalog changed since this re-sync was reviewed; review it again")
)

// Why a tool was skipped.
const (
	// SkipEdited: someone edited the tool by hand.
	SkipEdited = "edited"
	// SkipCustom: a tool made in the editor has the name.
	SkipCustom = "custom"
)

// What re-sync would do to a tool.
const (
	ChangeAdd    = "add"
	ChangeUpdate = "update"
	ChangeRemove = "remove"
)

// BundledFunc returns the adapter bundled for a catalog slug and its index
// entry, which carries its content hash and the hashes it had before. It
// returns an error wrapping fs.ErrNotExist for an unknown slug.
type BundledFunc func(slug string) (*adapter.Adapter, adapter.IndexEntry, error)

// ResyncPlan is what a re-sync changes. Apply recomputes it under the
// connector's lock, so the plan applied is the one the caller reviewed as
// long as the connector's version has not moved.
type ResyncPlan struct {
	// Connector is the connector as it is now.
	Connector *Connector
	// BundledHash is the content hash of the adapter this binary carries.
	BundledHash string
	Add         []ResyncTool
	Update      []ResyncTool
	Remove      []ResyncTool
	Skipped     []SkippedTool
	// Relabel are tools an older replica stored as imports; they stay,
	// and are marked as the catalog's.
	Relabel []ResyncTool
	// Fields are the connector settings re-sync replaces (instructions).
	Fields []FieldChange
	// NotApplied are the settings that differ from the bundled adapter but
	// that re-sync leaves for an operator to change (transport, auth).
	NotApplied []FieldChange
	// MissingCredentials are credentials the bundled adapter requires that
	// the connector does not have. Re-sync does not ask for them.
	MissingCredentials []string

	// Instructions is what the connector's instructions become.
	Instructions string

	entry adapter.IndexEntry
}

// ResyncTool is one tool a re-sync adds, rewrites or removes.
type ResyncTool struct {
	Name string
	// ToolID is empty for a tool not yet added.
	ToolID string
	// Changed lists the top-level definition fields an update rewrites.
	Changed []string
	// Before is the stored tool; nil for an add.
	Before *Tool
	// After is the bundled definition; nil for a remove.
	After *adapter.Tool
}

// SkippedTool is a tool the catalog would change but a person owns.
type SkippedTool struct {
	Name   string
	ToolID string
	// Reason is SkipEdited or SkipCustom.
	Reason string
	// Change is what re-sync would otherwise have done: ChangeAdd,
	// ChangeUpdate or ChangeRemove.
	Change string
}

// FieldChange is one connector-level setting that differs from the
// bundled adapter. Before and After are the value as text: the string
// for instructions, indented JSON for transport and auth.
type FieldChange struct {
	Field  string
	Before string
	After  string
}

// Outdated reports whether the connector came from an earlier version of
// the bundled adapter.
func (p *ResyncPlan) Outdated() bool { return p.entry.Precedes(p.Connector.CatalogHash) }

// Empty reports whether applying the plan would change no tool and no
// setting.
func (p *ResyncPlan) Empty() bool {
	return len(p.Add)+len(p.Update)+len(p.Remove)+len(p.Relabel)+len(p.Fields) == 0
}

// ResyncInput is what applying a re-sync needs besides the connector.
type ResyncInput struct {
	// CatalogHash is the bundled hash the caller reviewed. A replica
	// running a different binary refuses rather than apply its own.
	CatalogHash string
	// ExpectedVersion is the connector version the caller reviewed.
	ExpectedVersion int64
	// ActorID names who applied it.
	ActorID string
	// Authorize is called with the plan rebuilt inside the transaction,
	// before anything is written. An error from it rolls the re-sync back
	// and is returned as is. The permission a re-sync needs depends on
	// what it changes, so it is decided on the plan that is applied.
	Authorize func(*ResyncPlan) error
}

// PlanResync compares a catalog connector with its bundled adapter.
func (s *Service) PlanResync(ctx context.Context, orgID, id string, bundled BundledFunc) (*ResyncPlan, error) {
	var plan *ResyncPlan
	err := s.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		c, err := scanConnector(tx.QueryRow(ctx, selectConnector+` WHERE c.id = $1`, id))
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		plan, err = planResyncTx(ctx, tx, c, bundled, "")
		return err
	})
	if err != nil {
		return nil, err
	}
	return plan, nil
}

// ApplyResync applies the re-sync of a catalog connector in one
// transaction: tools added, rewritten and removed, the connector's
// settings and catalog_hash updated, the connector and server versions
// bumped so every replica's tool list rebuilds, and a revision recorded
// for the connector and for each tool it touched. It returns the plan it
// applied; an up-to-date connector is left untouched.
func (s *Service) ApplyResync(ctx context.Context, orgID, id string, bundled BundledFunc, in ResyncInput) (*ResyncPlan, error) {
	var plan *ResyncPlan
	err := s.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		c, err := lockConnector(ctx, tx, id)
		if err != nil {
			return err
		}
		if c.Version != in.ExpectedVersion {
			return ErrResyncStale
		}
		plan, err = planResyncTx(ctx, tx, c, bundled, " FOR NO KEY UPDATE")
		if err != nil {
			return err
		}
		if plan.BundledHash != in.CatalogHash {
			return ErrResyncStale
		}
		if plan.Empty() && !plan.Outdated() {
			return nil
		}
		if in.Authorize != nil {
			if err := in.Authorize(plan); err != nil {
				return err
			}
		}
		return s.applyResyncTx(ctx, tx, plan, in.ActorID)
	})
	if err != nil {
		return nil, err
	}
	return plan, nil
}

// planResyncTx reads the connector's tools (lock appended to the query)
// and credential names, and plans the re-sync.
func planResyncTx(ctx context.Context, tx pgx.Tx, c *Connector, bundled BundledFunc, lock string) (*ResyncPlan, error) {
	if c.CatalogSlug == "" {
		return nil, ErrNotFromCatalog
	}
	a, entry, err := bundled(c.CatalogSlug)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%w: %s", ErrNotInCatalog, c.CatalogSlug)
	}
	if err != nil {
		return nil, err
	}
	if c.CatalogHash != entry.ContentHash && !entry.Precedes(c.CatalogHash) {
		return nil, ErrCatalogNotBehind
	}
	rows, err := tx.Query(ctx, selectTool+` WHERE t.connector_id = $1 ORDER BY t.name`+lock, c.ID)
	if err != nil {
		return nil, fmt.Errorf("read tools: %w", err)
	}
	stored, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (*Tool, error) { return scanTool(r) })
	if err != nil {
		return nil, fmt.Errorf("read tools: %w", err)
	}
	rows, err = tx.Query(ctx, `SELECT name FROM connector_credentials WHERE connector_id = $1`, c.ID)
	if err != nil {
		return nil, fmt.Errorf("read credential names: %w", err)
	}
	names, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, fmt.Errorf("read credential names: %w", err)
	}
	creds := make(map[string]bool, len(names))
	for _, n := range names {
		creds[n] = true
	}
	return planResync(c, stored, creds, a, entry)
}

// planResync is the comparison itself. stored is sorted by name.
func planResync(c *Connector, stored []*Tool, creds map[string]bool, a *adapter.Adapter, entry adapter.IndexEntry) (*ResyncPlan, error) {
	p := &ResyncPlan{Connector: c, BundledHash: entry.ContentHash, Instructions: a.Instructions, entry: entry}
	byName := make(map[string]*Tool, len(stored))
	for _, t := range stored {
		byName[t.Name] = t
	}
	inBundle := make(map[string]bool, len(a.Tools))
	for i := range a.Tools {
		b := &a.Tools[i]
		inBundle[b.Name] = true
		st, ok := byName[b.Name]
		if !ok {
			p.Add = append(p.Add, ResyncTool{Name: b.Name, After: b})
			continue
		}
		changed, err := definitionChanges(st.Definition, b)
		if err != nil {
			return nil, fmt.Errorf("compare tool %s: %w", b.Name, err)
		}
		if st.Source == ToolSourceImport && st.EditedAt == nil {
			p.Relabel = append(p.Relabel, ResyncTool{Name: st.Name, ToolID: st.ID, Before: st})
		}
		if len(changed) == 0 {
			continue
		}
		switch reason := skipReason(st); reason {
		case SkipCustom:
			p.Skipped = append(p.Skipped, SkippedTool{Name: st.Name, ToolID: st.ID, Reason: reason, Change: ChangeAdd})
		case SkipEdited:
			p.Skipped = append(p.Skipped, SkippedTool{Name: st.Name, ToolID: st.ID, Reason: reason, Change: ChangeUpdate})
		default:
			p.Update = append(p.Update, ResyncTool{Name: st.Name, ToolID: st.ID, Changed: changed, Before: st, After: b})
		}
	}
	for _, st := range stored {
		if inBundle[st.Name] {
			continue
		}
		switch reason := skipReason(st); reason {
		case SkipCustom:
			// The organisation's own tool; the catalog never had it.
		case SkipEdited:
			p.Skipped = append(p.Skipped, SkippedTool{Name: st.Name, ToolID: st.ID, Reason: reason, Change: ChangeRemove})
		default:
			p.Remove = append(p.Remove, ResyncTool{Name: st.Name, ToolID: st.ID, Before: st})
		}
	}
	sort.Slice(p.Add, func(i, j int) bool { return p.Add[i].Name < p.Add[j].Name })
	sort.Slice(p.Update, func(i, j int) bool { return p.Update[i].Name < p.Update[j].Name })
	sort.Slice(p.Skipped, func(i, j int) bool { return p.Skipped[i].Name < p.Skipped[j].Name })

	if c.Instructions != a.Instructions {
		p.Fields = append(p.Fields, FieldChange{Field: "instructions", Before: c.Instructions, After: a.Instructions})
	}
	for _, f := range []struct {
		name          string
		before, after any
	}{{"transport", c.Transport, a.Transport}, {"auth", c.Auth, a.Auth}} {
		b, err := canonicalText(f.before)
		if err != nil {
			return nil, fmt.Errorf("compare %s: %w", f.name, err)
		}
		af, err := canonicalText(f.after)
		if err != nil {
			return nil, fmt.Errorf("compare %s: %w", f.name, err)
		}
		if b != af {
			p.NotApplied = append(p.NotApplied, FieldChange{Field: f.name, Before: b, After: af})
		}
	}
	for _, name := range a.Credentials.Keys {
		if a.Credentials.Values[name].Required && !creds[name] {
			p.MissingCredentials = append(p.MissingCredentials, name)
		}
	}
	return p, nil
}

// skipReason says why re-sync must leave a stored tool alone, or "".
func skipReason(t *Tool) string {
	switch {
	case t.Source == ToolSourceCustom:
		return SkipCustom
	case t.EditedAt != nil:
		return SkipEdited
	}
	return ""
}

// definitionChanges lists the top-level fields in which two definitions
// differ, ignoring key order: a stored definition comes back from jsonb
// with its keys reordered, which is not a change.
func definitionChanges(before, after *adapter.Tool) ([]string, error) {
	b, err := definitionFields(before)
	if err != nil {
		return nil, err
	}
	a, err := definitionFields(after)
	if err != nil {
		return nil, err
	}
	var out []string
	for k, bv := range b {
		if av, ok := a[k]; !ok || !reflect.DeepEqual(bv, av) {
			out = append(out, k)
		}
	}
	for k := range a {
		if _, ok := b[k]; !ok {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out, nil
}

// definitionFields decodes a definition's storage form into generic
// values, numbers kept as written.
func definitionFields(t *adapter.Tool) (map[string]any, error) {
	raw, err := DefinitionJSON(t)
	if err != nil {
		return nil, err
	}
	return decodeGeneric(raw)
}

func decodeGeneric(raw []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	return m, nil
}

// canonicalText renders a value as indented JSON with sorted keys, so two
// values compare equal as text exactly when they are equal as JSON.
func canonicalText(v any) (string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	m, err := decodeGeneric(raw)
	if err != nil {
		return "", err
	}
	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// applyResyncTx writes the plan. The tool and connector writes go in one
// batch; the revisions follow, one per entity, because each takes its own
// entity's revision sequence.
func (s *Service) applyResyncTx(ctx context.Context, tx pgx.Tx, p *ResyncPlan, actorID string) error {
	c := p.Connector
	b := &pgx.Batch{}
	for i := range p.Add {
		t := &p.Add[i]
		// Written the way Install writes it, through DefinitionJSON.
		def, err := DefinitionJSON(t.After)
		if err != nil {
			return fmt.Errorf("encode tool %s: %w", t.Name, err)
		}
		t.ToolID = s.NewID()
		b.Queue(`INSERT INTO tools (id, connector_id, organization_id, name, definition, enabled, source) VALUES ($1,$2,$3,$4,$5,true,$6)`,
			t.ToolID, c.ID, c.OrgID, t.Name, def, ToolSourceCatalog)
	}
	var changedBehaviour []string
	for _, t := range p.Update {
		def, err := DefinitionJSON(t.After)
		if err != nil {
			return fmt.Errorf("encode tool %s: %w", t.Name, err)
		}
		b.Queue(`UPDATE tools SET definition = $2, source = $3, version = version + 1, updated_at = now() WHERE id = $1`,
			t.ToolID, def, ToolSourceCatalog)
		if BehaviourChanged(t.Before.Definition, t.After) {
			changedBehaviour = append(changedBehaviour, t.ToolID)
		}
	}
	removed := make([]string, 0, len(p.Remove))
	removedEnabled := 0
	for _, t := range p.Remove {
		removed = append(removed, t.ToolID)
		if t.Before.Enabled {
			removedEnabled++
		}
	}
	// An approval replays by tool id: a yes given to the old definition
	// must not run the new one, and one for a removed tool can never run.
	cancel := `UPDATE approval_requests SET state = 'cancelled', cancelled_at = now(), reason = $2
		WHERE tool_id = ANY($1) AND state IN ('pending', 'approved')`
	if len(changedBehaviour) > 0 {
		b.Queue(cancel, changedBehaviour, "the tool's definition changed")
	}
	if len(removed) > 0 {
		// DLP policies scoped to a tool go with it by foreign key;
		// tool_access_rules has none.
		b.Queue(`DELETE FROM tools WHERE id = ANY($1)`, removed)
		b.Queue(`DELETE FROM tool_access_rules WHERE tool_id = ANY($1)`, removed)
		b.Queue(cancel, removed, "the tool was removed from the catalog adapter")
	}
	if len(p.Relabel) > 0 {
		relabel := make([]string, 0, len(p.Relabel))
		for _, t := range p.Relabel {
			relabel = append(relabel, t.ToolID)
		}
		b.Queue(`UPDATE tools SET source = $2 WHERE id = ANY($1)`, relabel, ToolSourceCatalog)
	}
	// Transport and auth are left as they are; see NotApplied.
	b.Queue(`UPDATE connectors SET instructions = $2, catalog_hash = $3, version = version + 1, updated_at = now() WHERE id = $1`,
		c.ID, p.Instructions, p.BundledHash)
	b.Queue(`UPDATE mcp_servers SET version = version + 1, updated_at = now()
		WHERE id IN (SELECT server_id FROM mcp_server_connectors WHERE connector_id = $1)`, c.ID)
	if err := tx.SendBatch(ctx, b).Close(); err != nil {
		return mapToolWriteError(err)
	}
	return s.recordResync(ctx, tx, p, removedEnabled, actorID)
}

// recordResync records a revision of the connector and of every tool the
// re-sync added, rewrote or removed.
func (s *Service) recordResync(ctx context.Context, tx pgx.Tx, p *ResyncPlan, removedEnabled int, actorID string) error {
	before := *p.Connector
	after := before
	after.Instructions, after.CatalogHash = p.Instructions, p.BundledHash
	after.Version++
	after.ToolCount += len(p.Add) - removedEnabled
	if err := s.record(ctx, tx, "connector", before.ID, "update", &after, audit.Changes(before, &after), actorID); err != nil {
		return err
	}
	for _, t := range p.Add {
		snap, err := snapshotTool(&Tool{ID: t.ToolID, ConnectorID: before.ID, Name: t.Name, Definition: t.After,
			Enabled: true, Version: 1, Source: ToolSourceCatalog})
		if err != nil {
			return err
		}
		if err := s.record(ctx, tx, "tool", t.ToolID, "create", snap, audit.Created(snap), actorID); err != nil {
			return err
		}
	}
	for _, t := range p.Update {
		beforeSnap, err := snapshotTool(t.Before)
		if err != nil {
			return err
		}
		next := *t.Before
		next.Definition, next.Source = t.After, ToolSourceCatalog
		next.Version++
		afterSnap, err := snapshotTool(&next)
		if err != nil {
			return err
		}
		if err := s.recordBaseline(ctx, tx, "tool", t.ToolID, beforeSnap); err != nil {
			return err
		}
		if err := s.record(ctx, tx, "tool", t.ToolID, "update", afterSnap, audit.Changes(beforeSnap, afterSnap), actorID); err != nil {
			return err
		}
	}
	for _, t := range p.Remove {
		snap, err := snapshotTool(t.Before)
		if err != nil {
			return err
		}
		if err := s.recordBaseline(ctx, tx, "tool", t.ToolID, snap); err != nil {
			return err
		}
		if err := s.record(ctx, tx, "tool", t.ToolID, "delete", snap, audit.Deleted(snap), actorID); err != nil {
			return err
		}
	}
	return nil
}
