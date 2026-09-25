package dlp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/supermcpco/supermcp/internal/audit"
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

// ErrConcurrentChange is a write that lost a deadlock with another write
// to the same policies and detectors, which Postgres broke by aborting
// this one. Nothing was written; the same request can be sent again.
var ErrConcurrentChange = errors.New("a data-loss policy or detector was changed at the same moment; try again")

// ErrDetectorBroken is why a call is refused when its policy names a
// custom detector that cannot be compiled. It is always wrapped with
// ErrRefused: a rule that cannot run is not a rule that passed.
var ErrDetectorBroken = errors.New("a detector this policy names cannot run")

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
	// Detectors names which detectors run: built-in names, and the
	// organisation's own as custom:<name>. Empty means every built-in;
	// a custom detector runs only where a policy names it.
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
//
// A write through this reader drops its own cache entry at once. A write
// anywhere else — another reader, another replica — reaches InvalidateOrg
// through the invalidation listener, which the database notifies on
// commit. The expiry is the backstop for when the listener is not
// connected.
type Policies struct {
	DB    *tenant.DB
	NewID func() string
	// Revisions records each change beside the change itself, in the same
	// transaction. Nil records nothing.
	Revisions Recorder
	// OnInvalidate, when set, is told of each local invalidation (source
	// "local"), for the invalidation counter.
	OnInvalidate func(source string)
	// Log receives the one line written when a stored detector cannot be
	// compiled. Nil logs nothing.
	Log *slog.Logger

	// mu guards cache, gen, orgGen and compiled.
	mu    sync.Mutex
	cache map[string]cacheEntry
	// compiled holds each organisation's compiled custom detectors, keyed
	// by id@version. It outlives an invalidation, so a notification about
	// one detector does not recompile the others; a load replaces the
	// organisation's map with the detectors it read, so an edited or
	// deleted detector's old program goes with it.
	compiled map[string]map[string]Detector
	// gen counts full flushes and orgGen each organisation's
	// invalidations, so a read that was in flight when one landed does not
	// put back what it dropped. A full flush empties orgGen.
	gen    uint64
	orgGen map[string]uint64
	now    func() time.Time
}

// Recorder is the part of the revision history this package needs. It is
// an interface so the dependency points this way and not the other.
type Recorder interface {
	Record(ctx context.Context, tx pgx.Tx, kind, entityID, action string, entity any, diff *audit.Diff, actorID string) error
	// RecordBaseline records entity as the first revision when entityID
	// has none yet, and does nothing otherwise.
	RecordBaseline(ctx context.Context, tx pgx.Tx, kind, entityID string, entity any) error
}

// RevisionKind is what the revision history calls a policy.
const RevisionKind = "dlp_policy"

// DetectorRevisionKind is what the revision history calls a custom
// detector.
const DetectorRevisionKind = "dlp_detector"

// The actions a revision records.
const (
	revisionCreate = "create"
	revisionUpdate = "update"
	revisionDelete = "delete"
)

type cacheEntry struct {
	list []ScanPolicy
	// custom is the organisation's enabled custom detectors, compiled,
	// by the name a policy uses for them.
	custom map[string]Detector
	// broken is the enabled detectors that did not compile, by the same
	// name, with the reason. A policy naming one refuses every call it
	// screens. Kept in the entry, so the failure costs one compile per
	// load and not one per call.
	broken map[string]error
	at     time.Time
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
	return &Policies{DB: db, NewID: newID, cache: map[string]cacheEntry{}, orgGen: map[string]uint64{},
		compiled: map[string]map[string]Detector{}, now: time.Now}
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
		if slug, ok := IsCustom(name); ok {
			// Whether the organisation has it is a question for the
			// database, asked inside the writing transaction.
			if !ValidSlug(slug) {
				return fmt.Errorf("%w: no detector called %s", ErrInvalid, name)
			}
			continue
		}
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

// Options turns the stored names into the built-in detectors to run. A
// custom name is left out; OptionsWith resolves those.
func (p ScanPolicy) Options(root string) Options {
	opt, _ := p.OptionsWith(root, nil)
	return opt
}

// OptionsWith turns the stored names into the detectors to run, looking
// custom names up in custom (the organisation's enabled detectors, from
// Policies.Custom). ok is false when the policy names detectors and none
// of them can run — every one it names is a custom detector since
// disabled — and then nothing should be scanned at all: an empty list in
// Options means every built-in, which is not what the policy says.
func (p ScanPolicy) OptionsWith(root string, custom map[string]Detector) (opt Options, ok bool) {
	opt = Options{MaxBytes: p.MaxBytes, Root: root}
	if len(p.Detectors) == 0 {
		return opt, true
	}
	opt.Detectors = make([]Detector, 0, len(p.Detectors))
	for _, name := range p.Detectors {
		if d, found := byName[name]; found {
			opt.Detectors = append(opt.Detectors, d)
		} else if d, found := custom[name]; found {
			opt.Detectors = append(opt.Detectors, d)
		}
	}
	return opt, len(opt.Detectors) > 0
}

// Resolve returns the policy governing one call. The error is reported
// rather than swallowed: a policy that cannot be read is a decision the
// call site has to make, and refusing every tool call because one table is
// unreachable is rarely the right one.
func (p *Policies) Resolve(ctx context.Context, orgID, connectorID, toolID string) (ScanPolicy, bool, error) {
	if p == nil || orgID == "" {
		return ScanPolicy{}, false, nil
	}
	e, err := p.entry(ctx, orgID)
	if err != nil {
		return ScanPolicy{}, false, err
	}
	got, found := Select(e.list, connectorID, toolID)
	return got, found, nil
}

// Custom returns the organisation's enabled custom detectors by the name a
// policy uses for them, from the same cache the tool-call path reads.
func (p *Policies) Custom(ctx context.Context, orgID string) (map[string]Detector, error) {
	if p == nil || orgID == "" {
		return nil, nil
	}
	e, err := p.entry(ctx, orgID)
	if err != nil {
		return nil, err
	}
	return e.custom, nil
}

// entry is the organisation's cached policies and detectors, read again
// when they are missing or stale.
func (p *Policies) entry(ctx context.Context, orgID string) (cacheEntry, error) {
	p.mu.Lock()
	e, ok := p.cache[orgID]
	fresh := ok && p.now().Sub(e.at) < policyTTL
	p.mu.Unlock()
	if fresh {
		return e, nil
	}
	return p.load(ctx, orgID)
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
	e, err := p.entry(ctx, orgID)
	if err != nil {
		return out, err
	}
	out.Applied, out.ScanPolicy = true, rule
	for _, name := range rule.Detectors {
		if reason, ok := e.broken[name]; ok {
			return out, fmt.Errorf("%w: %w: %s (%w)", ErrRefused, ErrDetectorBroken, name, reason)
		}
	}
	opt, run := rule.OptionsWith("$."+string(stage), e.custom)
	if !run {
		return out, nil
	}
	opt.Deadline = scanDeadline(ctx, p.now())
	value, res, err := Apply(v, rule.Action, opt)
	out.Result = res
	if err != nil {
		return out, err
	}
	out.Value = value
	return out, nil
}

// scanDeadline is when a screen must have finished: MaxScanTime from now,
// or the call's own deadline when that comes first.
func scanDeadline(ctx context.Context, now time.Time) time.Time {
	dl := now.Add(MaxScanTime)
	if d, ok := ctx.Deadline(); ok && d.Before(dl) {
		dl = d
	}
	return dl
}

// List returns every policy in the organisation, oldest first, and
// refreshes the cache.
func (p *Policies) List(ctx context.Context, orgID string) ([]ScanPolicy, error) {
	e, err := p.load(ctx, orgID)
	if err != nil {
		return nil, err
	}
	return e.list, nil
}

// policyColumns is what every read of a policy selects, in the order
// scanPolicy reads it.
const policyColumns = `id, organization_id, name, COALESCE(connector_id,''), COALESCE(tool_id,''),
	scan, detectors, action, enabled, max_bytes, COALESCE(created_by,''), created_at, updated_at`

func scanPolicy(row pgx.CollectableRow) (ScanPolicy, error) {
	var v ScanPolicy
	err := row.Scan(&v.ID, &v.OrgID, &v.Name, &v.ConnectorID, &v.ToolID, &v.Scan, &v.Detectors,
		&v.Action, &v.Enabled, &v.MaxBytes, &v.CreatedBy, &v.CreatedAt, &v.UpdatedAt)
	return v, err
}

// load reads the organisation's policies and enabled custom detectors in
// one round trip, compiles the detectors it has not compiled at their
// current version, and refreshes the cache.
func (p *Policies) load(ctx context.Context, orgID string) (cacheEntry, error) {
	p.mu.Lock()
	gen, orgGen := p.gen, p.orgGen[orgID]
	prev := p.compiled[orgID]
	p.mu.Unlock()

	var list []ScanPolicy
	var stored []CustomDetector
	err := p.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		batch := &pgx.Batch{}
		batch.Queue(`SELECT `+policyColumns+` FROM dlp_policies WHERE organization_id = $1 ORDER BY created_at`, orgID)
		batch.Queue(`SELECT id, name, pattern, flags, version FROM dlp_detectors
			WHERE organization_id = $1 AND enabled`, orgID)
		br := tx.SendBatch(ctx, batch)
		rows, err := br.Query()
		if err == nil {
			list, err = pgx.CollectRows(rows, scanPolicy)
		}
		if err == nil {
			rows, err = br.Query()
		}
		if err == nil {
			stored, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (CustomDetector, error) {
				var c CustomDetector
				err := row.Scan(&c.ID, &c.Name, &c.Pattern, &c.Flags, &c.Version)
				return c, err
			})
		}
		return errors.Join(err, br.Close())
	})
	if err != nil {
		return cacheEntry{}, fmt.Errorf("read dlp policies: %w", err)
	}
	if list == nil {
		list = []ScanPolicy{}
	}

	// Compiled outside the lock: a pattern is at most 512 bytes and cheap
	// to compile, but the lock is on the tool-call path.
	compiled := make(map[string]Detector, len(stored))
	custom := make(map[string]Detector, len(stored))
	var broken map[string]error
	for _, c := range stored {
		key := c.ID + "@" + strconv.FormatInt(c.Version, 10)
		d, ok := prev[key]
		if !ok {
			// Every pattern saved through this package passed this same
			// check, so a failure means the rules changed under it or the
			// row was written by hand. Only this detector is lost: the
			// policies that name it refuse (see Screen), and every other
			// policy in the organisation screens as before.
			var cerr error
			if d, cerr = NewCustom(c); cerr != nil {
				if broken == nil {
					broken = map[string]error{}
				}
				broken[c.Ref()] = cerr
				if p.Log != nil {
					p.Log.Error("a stored data-loss detector cannot be compiled; the policies naming it refuse every call they screen",
						"org_id", orgID, "detector", c.Ref(), "detector_id", c.ID, "err", cerr)
				}
				continue
			}
		}
		compiled[key] = d
		custom[c.Ref()] = d
	}

	e := cacheEntry{list: list, custom: custom, broken: broken, at: p.now()}
	p.mu.Lock()
	if p.gen == gen && p.orgGen[orgID] == orgGen {
		p.cache[orgID] = e
		p.compiled[orgID] = compiled
	}
	p.mu.Unlock()
	return e, nil
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

// Create stores a new policy and returns it as stored. The creator is
// v.CreatedBy, which is also who the revision names.
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
		if err := customCheck(ctx, tx, v); err != nil {
			return err
		}
		if err := insertPolicy(ctx, tx, &v); err != nil {
			return err
		}
		return p.record(ctx, tx, v, revisionCreate, audit.Created(v), v.CreatedBy)
	})
	if err != nil {
		return ScanPolicy{}, concurrent(scopeConflict(err))
	}
	p.invalidate(orgID)
	return v, nil
}

// Update replaces a policy's settings. The scope is part of a policy's
// identity and is replaced with it, so moving a rule from a connector to
// one of its tools is one write.
func (p *Policies) Update(ctx context.Context, orgID, id string, v ScanPolicy, actorID string) (ScanPolicy, error) {
	if err := v.Validate(); err != nil {
		return ScanPolicy{}, err
	}
	v.ID, v.OrgID = id, orgID
	if v.Detectors == nil {
		v.Detectors = []string{}
	}
	err := p.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		before, err := lockPolicy(ctx, tx, orgID, id)
		if err != nil {
			return err
		}
		if err := scopeExists(ctx, tx, v); err != nil {
			return err
		}
		if err := customCheck(ctx, tx, v); err != nil {
			return err
		}
		if err := updatePolicy(ctx, tx, &v); err != nil {
			return err
		}
		if err := p.baseline(ctx, tx, before); err != nil {
			return err
		}
		return p.record(ctx, tx, v, revisionUpdate, audit.Changes(before, v), actorID)
	})
	if err != nil {
		return ScanPolicy{}, concurrent(scopeConflict(err))
	}
	p.invalidate(orgID)
	return v, nil
}

// Restore puts a policy back the way a revision recorded it, through the
// same statements an edit uses, so the change reaches every replica the
// way an edit does. A policy that has since been deleted is recreated
// under its old id, with its old creator, and the revision says so; one
// that still exists is updated. The scope is checked again either way: a
// rule for a connector that has gone cannot come back.
//
// It returns the policy as restored and the one it replaced, read under
// the row lock; the second is nil when the policy was recreated.
func (p *Policies) Restore(ctx context.Context, orgID, id string, v ScanPolicy, actorID string) (ScanPolicy, *ScanPolicy, error) {
	if err := v.Validate(); err != nil {
		return ScanPolicy{}, nil, err
	}
	v.ID, v.OrgID = id, orgID
	if v.Detectors == nil {
		v.Detectors = []string{}
	}
	var replaced *ScanPolicy
	err := p.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		before, err := lockPolicy(ctx, tx, orgID, id)
		switch {
		case errors.Is(err, ErrNotFound):
			if err := scopeExists(ctx, tx, v); err != nil {
				return err
			}
			if err := customCheck(ctx, tx, v); err != nil {
				return err
			}
			if err := insertPolicy(ctx, tx, &v); err != nil {
				return err
			}
			return p.record(ctx, tx, v, revisionCreate, audit.Created(v), actorID)
		case err != nil:
			return err
		}
		if err := scopeExists(ctx, tx, v); err != nil {
			return err
		}
		if err := customCheck(ctx, tx, v); err != nil {
			return err
		}
		if err := updatePolicy(ctx, tx, &v); err != nil {
			return err
		}
		if err := p.baseline(ctx, tx, before); err != nil {
			return err
		}
		if err := p.record(ctx, tx, v, revisionUpdate, audit.Changes(before, v), actorID); err != nil {
			return err
		}
		replaced = &before
		return nil
	})
	if err != nil {
		return ScanPolicy{}, nil, concurrent(scopeConflict(err))
	}
	p.invalidate(orgID)
	return v, replaced, nil
}

// Delete removes a policy. Its history stays, with the policy as it was
// last, so it can be restored.
func (p *Policies) Delete(ctx context.Context, orgID, id, actorID string) error {
	err := p.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		before, err := lockPolicy(ctx, tx, orgID, id)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM dlp_policies WHERE organization_id = $1 AND id = $2`, orgID, id); err != nil {
			return err
		}
		if err := p.baseline(ctx, tx, before); err != nil {
			return err
		}
		return p.record(ctx, tx, before, revisionDelete, audit.Deleted(before), actorID)
	})
	if err != nil {
		return err
	}
	p.invalidate(orgID)
	return nil
}

// lockPolicy reads a policy inside the writing transaction and holds its
// row, so the before a revision records is the one the write replaced.
func lockPolicy(ctx context.Context, tx pgx.Tx, orgID, id string) (ScanPolicy, error) {
	rows, err := tx.Query(ctx, `SELECT `+policyColumns+`
		FROM dlp_policies WHERE organization_id = $1 AND id = $2 FOR UPDATE`, orgID, id)
	if err != nil {
		return ScanPolicy{}, err
	}
	v, err := pgx.CollectExactlyOneRow(rows, scanPolicy)
	if errors.Is(err, pgx.ErrNoRows) {
		return ScanPolicy{}, ErrNotFound
	}
	return v, err
}

func insertPolicy(ctx context.Context, tx pgx.Tx, v *ScanPolicy) error {
	return tx.QueryRow(ctx, `INSERT INTO dlp_policies
		(id, organization_id, name, connector_id, tool_id, scan, detectors, action, enabled, max_bytes, created_by)
		VALUES ($1,$2,$3,NULLIF($4,''),NULLIF($5,''),$6,$7,$8,$9,$10,NULLIF($11,''))
		RETURNING created_at, updated_at`,
		v.ID, v.OrgID, v.Name, v.ConnectorID, v.ToolID, v.Scan, v.Detectors, v.Action, v.Enabled, v.MaxBytes, v.CreatedBy).
		Scan(&v.CreatedAt, &v.UpdatedAt)
}

func updatePolicy(ctx context.Context, tx pgx.Tx, v *ScanPolicy) error {
	err := tx.QueryRow(ctx, `UPDATE dlp_policies SET name = $3, connector_id = NULLIF($4,''), tool_id = NULLIF($5,''),
		scan = $6, detectors = $7, action = $8, enabled = $9, max_bytes = $10, updated_at = now()
		WHERE organization_id = $1 AND id = $2
		RETURNING COALESCE(created_by,''), created_at, updated_at`,
		v.OrgID, v.ID, v.Name, v.ConnectorID, v.ToolID, v.Scan, v.Detectors, v.Action, v.Enabled, v.MaxBytes).
		Scan(&v.CreatedBy, &v.CreatedAt, &v.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

// record writes the policy's revision when a history is configured.
func (p *Policies) record(ctx context.Context, tx pgx.Tx, v ScanPolicy, action string, diff *audit.Diff, actorID string) error {
	if p.Revisions == nil {
		return nil
	}
	return p.Revisions.Record(ctx, tx, RevisionKind, v.ID, action, v, diff, actorID)
}

// baseline records a policy as it stood before its first recorded change,
// for one written before policies had a history, so that version can be
// put back too.
func (p *Policies) baseline(ctx context.Context, tx pgx.Tx, before ScanPolicy) error {
	if p.Revisions == nil {
		return nil
	}
	return p.Revisions.RecordBaseline(ctx, tx, RevisionKind, before.ID, before)
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

// customCheck checks that every custom detector a policy names is one of
// this organisation's, under row-level security like scopeExists, and
// that together they fit ScanCostBudget at the bytes the policy reads.
// The rows are locked FOR SHARE until the policy's transaction ends, so a
// delete or an edit of one of them waits for it and then sees the policy
// that now names it, rather than both committing unchecked.
func customCheck(ctx context.Context, tx pgx.Tx, v ScanPolicy) error {
	var want []string
	for _, n := range v.Detectors {
		if slug, ok := IsCustom(n); ok && !slices.Contains(want, slug) {
			want = append(want, slug)
		}
	}
	if len(want) == 0 {
		return nil
	}
	rows, err := tx.Query(ctx, `SELECT name, pattern, flags FROM dlp_detectors WHERE name = ANY($1) FOR SHARE`, want)
	if err != nil {
		return err
	}
	type named struct{ name, pattern, flags string }
	have, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (named, error) {
		var n named
		err := row.Scan(&n.name, &n.pattern, &n.flags)
		return n, err
	})
	if err != nil {
		return err
	}
	sizes := make([]int, 0, len(have))
	for _, slug := range want {
		i := slices.IndexFunc(have, func(n named) bool { return n.name == slug })
		if i < 0 {
			return fmt.Errorf("%w: no detector called %s%s in this organisation", ErrInvalid, CustomPrefix, slug)
		}
		size, err := ProgramSize(have[i].pattern, have[i].flags)
		if err != nil {
			return fmt.Errorf("%w: the detector %s%s cannot be compiled", ErrInvalid, CustomPrefix, slug)
		}
		sizes = append(sizes, size)
	}
	if total, limit := scanCost(sizes, v.MaxBytes); total > limit {
		return fmt.Errorf("%w: the custom detectors this policy names compile to %d instructions, and a policy reading %d bytes may run at most %d; name fewer or simpler ones, or lower maxBytes",
			ErrInvalid, total, effectiveMaxBytes(v.MaxBytes), limit)
	}
	return nil
}

func effectiveMaxBytes(n int) int {
	if n <= 0 {
		return DefaultMaxBytes
	}
	return n
}

// concurrent turns a deadlock Postgres broke by aborting this transaction
// into ErrConcurrentChange. A policy write locks its row and then the
// detectors it names; a detector delete locks the detector and then the
// policies naming it; the two can meet the other way round.
func concurrent(err error) error {
	var pge *pgconn.PgError
	// 40P01 is deadlock_detected.
	if errors.As(err, &pge) && pge.Code == "40P01" {
		return fmt.Errorf("%w (%w)", ErrConcurrentChange, err)
	}
	return err
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

// invalidate is the local path, after a write through this reader.
func (p *Policies) invalidate(orgID string) {
	p.InvalidateOrg(orgID)
	if p.OnInvalidate != nil {
		p.OnInvalidate("local")
	}
}

// InvalidateOrg drops one organisation's cached policies.
func (p *Policies) InvalidateOrg(orgID string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	delete(p.cache, orgID)
	p.orgGen[orgID]++
	p.mu.Unlock()
}

// InvalidateAll drops every cached policy.
func (p *Policies) InvalidateAll() {
	if p == nil {
		return
	}
	p.mu.Lock()
	clear(p.cache)
	clear(p.orgGen)
	p.gen++
	p.mu.Unlock()
	// compiled is kept: it is keyed by version, so nothing in it can be
	// stale, and the next load of each organisation prunes it.
}

func newUUID() string {
	id, err := uuid.NewV7()
	if err != nil {
		return uuid.NewString()
	}
	return id.String()
}
