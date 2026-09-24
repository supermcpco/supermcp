package dlp

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/supermcpco/supermcp/internal/tenant"
)

// What a tool call may carry is the organisation's decision, and it is not
// one decision: the rule for a support desk is not the rule for a payments
// system. A policy is therefore scoped — to the organisation, to one
// connector, or to one tool — and the narrowest scope that matches is the
// one that applies.

// policyTTL keeps the read off the tool-call path without making a change
// take effect tomorrow. It matches internal/audit, so an administrator
// waits the same time for either policy to come into force.
const policyTTL = 30 * time.Second

// maxFindingPaths is how many distinct paths one recorded row names. A
// field name is metadata, but a thousand of them is a record nobody reads.
const maxFindingPaths = 20

// maxFindingRows bounds the rows one call can write.
const maxFindingRows = 32

// ErrNotFound is returned for a policy that does not exist, or belongs to
// another organisation.
var ErrNotFound = errors.New("dlp policy not found")

// ErrInvalid marks a policy the caller could fix.
var ErrInvalid = errors.New("the policy is not valid")

// Stage is one half of a tool call: what went out, or what came back.
type Stage string

// The two stages, and the setting that means both.
const (
	StageArguments Stage = "arguments"
	StageResult    Stage = "result"
	StageBoth      Stage = "both"
)

// ScanPolicy is one organisation's rule about one scope.
type ScanPolicy struct {
	ID    string `json:"id"`
	OrgID string `json:"-"`
	Name  string `json:"name"`
	// ConnectorID and ToolID narrow the policy. Empty means the whole
	// organisation; a tool-scoped policy replaces a connector-scoped one,
	// which replaces the organisation's.
	ConnectorID string `json:"connectorId,omitempty"`
	ToolID      string `json:"toolId,omitempty"`
	Scan        Stage  `json:"scan" enum:"arguments,result,both"`
	// Detectors names which built-ins run. Empty means all of them.
	Detectors []string  `json:"detectors" nullable:"false"`
	Action    Action    `json:"action" enum:"allow,mask,refuse"`
	Enabled   bool      `json:"enabled"`
	MaxBytes  int       `json:"maxBytes,omitempty" doc:"How much of a value to scan; zero is the built-in cap"`
	CreatedBy string    `json:"createdBy,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// Policies reads and writes the policies, with a short cache in front of
// the read the tool-call path makes.
type Policies struct {
	DB    *tenant.DB
	NewID func() string

	mu    sync.Mutex
	cache map[string]cacheEntry
	now   func() time.Time
}

type cacheEntry struct {
	list []ScanPolicy
	at   time.Time
}

// Screened is the outcome of running a policy over one half of a call.
type Screened struct {
	// Value is what may go on: the value as it came in, or a masked copy.
	Value any
	// ScanPolicy is the rule that applied, and Applied says one did. A call
	// with no policy, or whose policy does not cover this half, comes back
	// unchanged with Applied false.
	Applied    bool
	ScanPolicy ScanPolicy
	Result     Result
}

// Recording is what one scan is worth storing about one call.
type Recording struct {
	InvocationID string
	PolicyID     string
	ConnectorID  string
	ToolID       string
	ToolName     string
	Stage        Stage
	Action       Action
	Result       Result
}

// NewPolicies builds the reader and writer. A nil db returns nil, so a
// cut-down build can tell that the feature is not configured. A nil newID
// mints UUIDv7, like every other identifier in the schema.
func NewPolicies(db *tenant.DB, newID func() string) *Policies {
	if db == nil {
		return nil
	}
	if newID == nil {
		newID = newUUID
	}
	return &Policies{DB: db, NewID: newID, cache: map[string]cacheEntry{}, now: time.Now}
}

// Select returns the policy that governs a call, from a list already read.
// The narrowest matching scope wins: a rule written for one tool replaces
// the connector's, which replaces the organisation's.
//
// Two policies cannot share a scope — the schema forbids it — so the
// tie-break below only matters to a caller holding a hand-built list. When
// it does, the stricter action wins: two rules of the same reach must not
// disagree into permissiveness.
func Select(list []ScanPolicy, connectorID, toolID string) (ScanPolicy, bool) {
	var best ScanPolicy
	found := false
	for _, p := range list {
		if !p.matches(connectorID, toolID) {
			continue
		}
		if !found || better(p, best) {
			best, found = p, true
		}
	}
	return best, found
}

// Validate checks a policy before it is stored.
func (p ScanPolicy) Validate() error {
	if strings.TrimSpace(p.Name) == "" {
		return fmt.Errorf("%w: it needs a name", ErrInvalid)
	}
	switch p.Scan {
	case StageArguments, StageResult, StageBoth:
	default:
		return fmt.Errorf("%w: scan must be arguments, result or both", ErrInvalid)
	}
	switch p.Action {
	case ActionAllow, ActionMask, ActionRefuse:
	default:
		return fmt.Errorf("%w: the action must be allow, mask or refuse", ErrInvalid)
	}
	if p.ToolID != "" && p.ConnectorID == "" {
		// A tool belongs to a connector, and a policy that named the tool
		// without it could not be told apart from the connector's own rule
		// when the two were listed side by side.
		return fmt.Errorf("%w: a tool-scoped policy must name the tool's connector too", ErrInvalid)
	}
	for _, name := range p.Detectors {
		if _, ok := byName[name]; !ok {
			return fmt.Errorf("%w: no detector called %s", ErrInvalid, name)
		}
	}
	if p.MaxBytes < 0 {
		return fmt.Errorf("%w: maxBytes cannot be negative", ErrInvalid)
	}
	return nil
}

// Covers reports whether the policy applies to one half of a call.
func (p ScanPolicy) Covers(s Stage) bool { return p.Scan == StageBoth || p.Scan == s }

// Options turns the stored names into the detectors to run.
func (p ScanPolicy) Options(root string) Options {
	opt := Options{MaxBytes: p.MaxBytes, Root: root}
	if len(p.Detectors) == 0 {
		return opt
	}
	opt.Detectors = make([]Detector, 0, len(p.Detectors))
	for _, name := range p.Detectors {
		if d, ok := byName[name]; ok {
			opt.Detectors = append(opt.Detectors, d)
		}
	}
	return opt
}

// Resolve returns the policy governing one call. The error is reported
// rather than swallowed: a policy that cannot be read is a decision the
// call site has to make, and refusing every tool call because one table is
// unreachable is rarely the right one.
func (p *Policies) Resolve(ctx context.Context, orgID, connectorID, toolID string) (ScanPolicy, bool, error) {
	if p == nil || orgID == "" {
		return ScanPolicy{}, false, nil
	}
	p.mu.Lock()
	e, ok := p.cache[orgID]
	fresh := ok && p.now().Sub(e.at) < policyTTL
	p.mu.Unlock()
	if !fresh {
		list, err := p.List(ctx, orgID)
		if err != nil {
			return ScanPolicy{}, false, err
		}
		e = cacheEntry{list: list, at: p.now()}
	}
	got, found := Select(e.list, connectorID, toolID)
	return got, found, nil
}

// Screen is the tool-call path in one call: find the rule that governs
// this call and apply it to one half of it.
//
// A refusal comes back as ErrRefused. Any other error means the policy
// could not be read, and Value is then what came in: whether a tool call
// should proceed when its rules are unreadable is a decision for the call
// site, not for a cache miss.
func (p *Policies) Screen(ctx context.Context, orgID, connectorID, toolID string, stage Stage, v any) (Screened, error) {
	out := Screened{Value: v}
	if p == nil || v == nil {
		return out, nil
	}
	rule, found, err := p.Resolve(ctx, orgID, connectorID, toolID)
	if err != nil {
		return out, err
	}
	if !found || !rule.Covers(stage) {
		return out, nil
	}
	out.Applied, out.ScanPolicy = true, rule
	value, res, err := Apply(v, rule.Action, rule.Options("$."+string(stage)))
	out.Result = res
	if err != nil {
		return out, err
	}
	out.Value = value
	return out, nil
}

// List returns every policy in the organisation, newest scope first, and
// refreshes the cache.
func (p *Policies) List(ctx context.Context, orgID string) ([]ScanPolicy, error) {
	out := []ScanPolicy{}
	err := p.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id, organization_id, name, COALESCE(connector_id,''), COALESCE(tool_id,''),
			scan, detectors, action, enabled, max_bytes, COALESCE(created_by,''), created_at, updated_at
			FROM dlp_policies WHERE organization_id = $1 ORDER BY created_at`, orgID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var v ScanPolicy
			if err := rows.Scan(&v.ID, &v.OrgID, &v.Name, &v.ConnectorID, &v.ToolID, &v.Scan, &v.Detectors,
				&v.Action, &v.Enabled, &v.MaxBytes, &v.CreatedBy, &v.CreatedAt, &v.UpdatedAt); err != nil {
				return err
			}
			out = append(out, v)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("read dlp policies: %w", err)
	}
	p.mu.Lock()
	p.cache[orgID] = cacheEntry{list: out, at: p.now()}
	p.mu.Unlock()
	return out, nil
}

// Get returns one policy.
func (p *Policies) Get(ctx context.Context, orgID, id string) (ScanPolicy, error) {
	list, err := p.List(ctx, orgID)
	if err != nil {
		return ScanPolicy{}, err
	}
	for _, v := range list {
		if v.ID == id {
			return v, nil
		}
	}
	return ScanPolicy{}, ErrNotFound
}

// Create stores a new policy and returns it as stored.
func (p *Policies) Create(ctx context.Context, orgID string, v ScanPolicy) (ScanPolicy, error) {
	if err := v.Validate(); err != nil {
		return ScanPolicy{}, err
	}
	v.ID, v.OrgID = p.NewID(), orgID
	if v.Detectors == nil {
		v.Detectors = []string{}
	}
	err := p.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		if err := scopeExists(ctx, tx, v); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `INSERT INTO dlp_policies
			(id, organization_id, name, connector_id, tool_id, scan, detectors, action, enabled, max_bytes, created_by)
			VALUES ($1,$2,$3,NULLIF($4,''),NULLIF($5,''),$6,$7,$8,$9,$10,NULLIF($11,''))
			RETURNING created_at, updated_at`,
			v.ID, orgID, v.Name, v.ConnectorID, v.ToolID, v.Scan, v.Detectors, v.Action, v.Enabled, v.MaxBytes, v.CreatedBy).
			Scan(&v.CreatedAt, &v.UpdatedAt)
	})
	if err != nil {
		return ScanPolicy{}, scopeConflict(err)
	}
	p.invalidate(orgID)
	return v, nil
}

// Update replaces a policy's settings. The scope is part of a policy's
// identity and is replaced with it, so moving a rule from a connector to
// one of its tools is one write.
func (p *Policies) Update(ctx context.Context, orgID, id string, v ScanPolicy) (ScanPolicy, error) {
	if err := v.Validate(); err != nil {
		return ScanPolicy{}, err
	}
	v.ID, v.OrgID = id, orgID
	if v.Detectors == nil {
		v.Detectors = []string{}
	}
	err := p.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		if err := scopeExists(ctx, tx, v); err != nil {
			return err
		}
		err := tx.QueryRow(ctx, `UPDATE dlp_policies SET name = $3, connector_id = NULLIF($4,''), tool_id = NULLIF($5,''),
			scan = $6, detectors = $7, action = $8, enabled = $9, max_bytes = $10, updated_at = now()
			WHERE organization_id = $1 AND id = $2
			RETURNING COALESCE(created_by,''), created_at, updated_at`,
			orgID, id, v.Name, v.ConnectorID, v.ToolID, v.Scan, v.Detectors, v.Action, v.Enabled, v.MaxBytes).
			Scan(&v.CreatedBy, &v.CreatedAt, &v.UpdatedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return err
	})
	if err != nil {
		return ScanPolicy{}, scopeConflict(err)
	}
	p.invalidate(orgID)
	return v, nil
}

// Delete removes a policy.
func (p *Policies) Delete(ctx context.Context, orgID, id string) error {
	err := p.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM dlp_policies WHERE organization_id = $1 AND id = $2`, orgID, id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return nil
	})
	if err != nil {
		return err
	}
	p.invalidate(orgID)
	return nil
}

// Record stores what a scan found, aggregated: one row per detector and
// rule, with how many times it matched and the fields it matched in. The
// values themselves are not stored and cannot be reconstructed from what
// is — see 00011_dlp.sql.
func (p *Policies) Record(ctx context.Context, orgID string, rec Recording) error {
	rows := aggregate(rec)
	if len(rows) == 0 {
		return nil
	}
	err := p.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		batch := &pgx.Batch{}
		for _, r := range rows {
			batch.Queue(`INSERT INTO dlp_findings (id, organization_id, invocation_id, policy_id, connector_id,
				tool_id, tool_name, stage, action, detector, rule, kind, confidence, matches, paths, truncated)
				VALUES ($1,$2,NULLIF($3,''),NULLIF($4,''),NULLIF($5,''),NULLIF($6,''),$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
				p.NewID(), orgID, rec.InvocationID, rec.PolicyID, rec.ConnectorID, rec.ToolID, rec.ToolName,
				rec.Stage, rec.Action, r.detector, r.rule, r.kind, r.confidence, r.matches, r.paths, rec.Result.Truncated)
		}
		br := tx.SendBatch(ctx, batch)
		return br.Close()
	})
	if err != nil {
		return fmt.Errorf("record dlp findings: %w", err)
	}
	return nil
}

// --- helpers ---------------------------------------------------------------

// matches reports whether a policy's scope covers this call. A policy that
// names a connector or a tool the call is not about never applies.
func (p ScanPolicy) matches(connectorID, toolID string) bool {
	switch {
	case !p.Enabled:
		return false
	case p.ConnectorID != "" && p.ConnectorID != connectorID:
		return false
	case p.ToolID != "" && p.ToolID != toolID:
		return false
	}
	return true
}

func (p ScanPolicy) specificity() int {
	switch {
	case p.ToolID != "":
		return 2
	case p.ConnectorID != "":
		return 1
	}
	return 0
}

// better reports whether a should replace b as the policy that applies.
func better(a, b ScanPolicy) bool {
	if a.specificity() != b.specificity() {
		return a.specificity() > b.specificity()
	}
	if strictness(a.Action) != strictness(b.Action) {
		return strictness(a.Action) > strictness(b.Action)
	}
	return a.ID < b.ID
}

func strictness(a Action) int {
	switch a {
	case ActionRefuse:
		return 2
	case ActionMask:
		return 1
	}
	return 0
}

// scopeExists checks that a connector or tool named by a policy is one of
// this organisation's. The read runs inside the tenant transaction, so
// row-level security answers the question; without it a policy could name
// an identifier from another tenant and say whether it exists.
func scopeExists(ctx context.Context, tx pgx.Tx, v ScanPolicy) error {
	if v.ConnectorID != "" {
		var ok bool
		if err := tx.QueryRow(ctx, `SELECT true FROM connectors WHERE id = $1`, v.ConnectorID).Scan(&ok); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return fmt.Errorf("%w: no connector %s in this organisation", ErrInvalid, v.ConnectorID)
			}
			return err
		}
	}
	if v.ToolID != "" {
		var ok bool
		if err := tx.QueryRow(ctx, `SELECT true FROM tools WHERE id = $1 AND connector_id = $2`,
			v.ToolID, v.ConnectorID).Scan(&ok); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return fmt.Errorf("%w: no tool %s on connector %s", ErrInvalid, v.ToolID, v.ConnectorID)
			}
			return err
		}
	}
	return nil
}

// scopeConflict turns the unique index into something an administrator can
// act on: the scope already has a rule, and a scope has exactly one.
func scopeConflict(err error) error {
	var pge *pgconn.PgError
	// 23505 is unique_violation; the index it breaks is the one that keeps
	// a scope to a single rule.
	if errors.As(err, &pge) && pge.Code == "23505" {
		return fmt.Errorf("%w: this connector or tool already has a rule, and a scope has exactly one; change the rule that is there, or narrow this one to a connector or a tool that has none", ErrInvalid)
	}
	return err
}

type findingRow struct {
	detector, rule, kind, confidence string
	matches                          int
	paths                            []string
}

// aggregate folds a scan's findings into the rows the table stores.
func aggregate(rec Recording) []findingRow {
	index := map[string]int{}
	var rows []findingRow
	for _, f := range rec.Result.Findings {
		key := f.Detector + "\x00" + f.Rule + "\x00" + string(f.Confidence)
		i, ok := index[key]
		if !ok {
			if len(rows) >= maxFindingRows {
				continue
			}
			rows = append(rows, findingRow{detector: f.Detector, rule: f.Rule,
				kind: string(f.Kind), confidence: string(f.Confidence), paths: []string{}})
			i = len(rows) - 1
			index[key] = i
		}
		rows[i].matches++
		if len(rows[i].paths) < maxFindingPaths && !slices.Contains(rows[i].paths, f.Path) {
			rows[i].paths = append(rows[i].paths, f.Path)
		}
	}
	return rows
}

func (p *Policies) invalidate(orgID string) {
	p.mu.Lock()
	delete(p.cache, orgID)
	p.mu.Unlock()
}

func newUUID() string {
	id, err := uuid.NewV7()
	if err != nil {
		return uuid.NewString()
	}
	return id.String()
}
