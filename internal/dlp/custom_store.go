package dlp

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/supermcpco/supermcp/internal/audit"
	"github.com/supermcpco/supermcp/internal/tenant"
)

// The custom detectors are written through the same reader as the
// policies: a write drops this replica's cached entry for the
// organisation, and the table's trigger (00031) tells every other
// replica on commit, exactly as a policy write does.

// DetectorPatch is a change to a detector. A nil field is left as it is.
// The name is not here: policies refer to a detector by it.
type DetectorPatch struct {
	Description  *string
	Pattern      *string
	Flags        *string
	MustMatch    *[]string
	MustNotMatch *[]string
	Enabled      *bool
}

// PolicyChange is one policy a forced delete edited, as it was and as it
// is now.
type PolicyChange struct {
	Before ScanPolicy
	After  ScanPolicy
}

// DetectorRecord is a detector as the revision history and the audit trail
// keep it: everything but the samples, of which it keeps the count. The
// samples are shaped like the values the detector exists to keep out of
// records, and a digest of one would not hide it: a contract id of six
// digits is a million guesses away from any hash of it (00011_dlp.sql
// makes the same argument about findings). They live in the detector's
// row alone.
type DetectorRecord struct {
	ID                string    `json:"id"`
	Name              string    `json:"name"`
	Detector          string    `json:"detector"`
	Description       string    `json:"description"`
	Pattern           string    `json:"pattern"`
	Flags             string    `json:"flags"`
	MustMatchCount    int       `json:"mustMatchCount"`
	MustNotMatchCount int       `json:"mustNotMatchCount"`
	Enabled           bool      `json:"enabled"`
	Version           int64     `json:"version"`
	CreatedBy         string    `json:"createdBy,omitempty"`
	UpdatedBy         string    `json:"updatedBy,omitempty"`
	CreatedAt         time.Time `json:"createdAt"`
	UpdatedAt         time.Time `json:"updatedAt"`
}

// Recorded is the detector as the history and the audit trail keep it.
func (c CustomDetector) Recorded() DetectorRecord {
	return DetectorRecord{ID: c.ID, Name: c.Name, Detector: c.Ref(), Description: c.Description, Pattern: c.Pattern,
		Flags: c.Flags, MustMatchCount: len(c.MustMatch), MustNotMatchCount: len(c.MustNotMatch), Enabled: c.Enabled,
		Version: c.Version, CreatedBy: c.CreatedBy, UpdatedBy: c.UpdatedBy, CreatedAt: c.CreatedAt, UpdatedAt: c.UpdatedAt}
}

const detectorColumns = `id, organization_id, name, description, pattern, flags, must_match, must_not_match,
	enabled, version, COALESCE(created_by,''), COALESCE(updated_by,''), created_at, updated_at`

func scanDetector(row pgx.CollectableRow) (CustomDetector, error) {
	var c CustomDetector
	err := row.Scan(&c.ID, &c.OrgID, &c.Name, &c.Description, &c.Pattern, &c.Flags, &c.MustMatch, &c.MustNotMatch,
		&c.Enabled, &c.Version, &c.CreatedBy, &c.UpdatedBy, &c.CreatedAt, &c.UpdatedAt)
	c.Detector = c.Ref()
	return c, err
}

// ListDetectors returns the organisation's custom detectors by name.
func (p *Policies) ListDetectors(ctx context.Context, orgID string) ([]CustomDetector, error) {
	var out []CustomDetector
	err := p.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+detectorColumns+` FROM dlp_detectors
			WHERE organization_id = $1 ORDER BY name`, orgID)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, scanDetector)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("read dlp detectors: %w", err)
	}
	if out == nil {
		out = []CustomDetector{}
	}
	return out, nil
}

// GetDetector returns one custom detector.
func (p *Policies) GetDetector(ctx context.Context, orgID, id string) (CustomDetector, error) {
	var out CustomDetector
	err := p.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		var err error
		out, err = readDetector(ctx, tx, orgID, id, "")
		return err
	})
	return out, err
}

// CreateDetector validates and stores a new detector. The creator is
// c.CreatedBy, which is also who the revision names.
func (p *Policies) CreateDetector(ctx context.Context, orgID string, c CustomDetector) (CustomDetector, error) {
	c = normalise(c)
	if err := c.Validate(); err != nil {
		return CustomDetector{}, err
	}
	c.ID, c.OrgID, c.UpdatedBy = p.NewID(), orgID, c.CreatedBy
	err := p.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		if err := insertDetector(ctx, tx, &c); err != nil {
			return err
		}
		return p.recordDetector(ctx, tx, c, revisionCreate, audit.Created(c.Recorded()), c.CreatedBy)
	})
	if err != nil {
		return CustomDetector{}, err
	}
	p.invalidate(orgID)
	return c, nil
}

// UpdateDetector applies a patch to the detector at expectedVersion. The
// whole detector is validated again as it would be stored, samples
// included, so an edit to the pattern that breaks a sample saved earlier
// is refused.
func (p *Policies) UpdateDetector(ctx context.Context, orgID, id string, patch DetectorPatch, expectedVersion int64, actorID string) (CustomDetector, CustomDetector, error) {
	var before, after CustomDetector
	err := p.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		var err error
		before, err = readDetector(ctx, tx, orgID, id, "FOR UPDATE")
		if err != nil {
			return err
		}
		if expectedVersion != before.Version {
			return &VersionConflictError{Current: before.Version}
		}
		after = normalise(patch.apply(before))
		if err := after.Validate(); err != nil {
			return err
		}
		if err := policiesFit(ctx, tx, orgID, after); err != nil {
			return err
		}
		after.UpdatedBy = actorID
		if err := updateDetector(ctx, tx, &after); err != nil {
			return err
		}
		if err := p.detectorBaseline(ctx, tx, before); err != nil {
			return err
		}
		return p.recordDetector(ctx, tx, after, revisionUpdate, audit.Changes(before.Recorded(), after.Recorded()), actorID)
	})
	if err != nil {
		return CustomDetector{}, CustomDetector{}, concurrent(err)
	}
	p.invalidate(orgID)
	return before, after, nil
}

// DeleteDetector removes a detector. When policies name it, the delete is
// refused with an *InUseError listing them, unless force is set: then it
// is taken out of each of those policies in the same transaction, and
// each policy's change is recorded in its history. A policy left naming
// no detector at all is also switched off, because an empty list means
// every built-in, and a rule written for one customer-number pattern
// should not wake up masking card numbers.
func (p *Policies) DeleteDetector(ctx context.Context, orgID, id string, force bool, actorID string) (CustomDetector, []PolicyChange, error) {
	var before CustomDetector
	var changes []PolicyChange
	err := p.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		var err error
		before, err = readDetector(ctx, tx, orgID, id, "FOR UPDATE")
		if err != nil {
			return err
		}
		ref := before.Ref()
		rows, err := tx.Query(ctx, `SELECT `+policyColumns+` FROM dlp_policies
			WHERE organization_id = $1 AND $2 = ANY(detectors) ORDER BY created_at FOR UPDATE`, orgID, ref)
		if err != nil {
			return err
		}
		users, err := pgx.CollectRows(rows, scanPolicy)
		if err != nil {
			return err
		}
		if len(users) > 0 && !force {
			inUse := &InUseError{}
			for _, u := range users {
				inUse.Policies = append(inUse.Policies, PolicyRef{ID: u.ID, Name: u.Name})
			}
			return inUse
		}
		if len(users) > 0 {
			rows, err := tx.Query(ctx, `UPDATE dlp_policies
				SET detectors = array_remove(detectors, $2),
				    enabled = enabled AND cardinality(array_remove(detectors, $2)) > 0,
				    updated_at = now()
				WHERE organization_id = $1 AND $2 = ANY(detectors)
				RETURNING `+policyColumns, orgID, ref)
			if err != nil {
				return err
			}
			updated, err := pgx.CollectRows(rows, scanPolicy)
			if err != nil {
				return err
			}
			for _, a := range updated {
				i := slices.IndexFunc(users, func(u ScanPolicy) bool { return u.ID == a.ID })
				if i < 0 {
					continue
				}
				changes = append(changes, PolicyChange{Before: users[i], After: a})
			}
			// One revision per policy: the recorder writes one entity's
			// history at a time, and the number is bounded by the
			// organisation's policies.
			for _, c := range changes {
				if err := p.baseline(ctx, tx, c.Before); err != nil {
					return err
				}
				if err := p.record(ctx, tx, c.After, revisionUpdate, audit.Changes(c.Before, c.After), actorID); err != nil {
					return err
				}
			}
		}
		if _, err := tx.Exec(ctx, `DELETE FROM dlp_detectors WHERE organization_id = $1 AND id = $2`, orgID, id); err != nil {
			return err
		}
		if err := p.detectorBaseline(ctx, tx, before); err != nil {
			return err
		}
		return p.recordDetector(ctx, tx, before, revisionDelete, audit.Deleted(before.Recorded()), actorID)
	})
	if err != nil {
		return CustomDetector{}, nil, concurrent(err)
	}
	p.invalidate(orgID)
	return before, changes, nil
}

// RestoreDetector puts a detector back the way a revision recorded it,
// through the statements an edit uses. The history holds no samples (see
// DetectorRecord), so a detector that still exists keeps the samples it
// has now, and the restored pattern is checked against them: samplesKept
// is true. A detector since deleted is recreated under its old id and
// name with no samples, since there are none left to keep, and
// samplesKept is false. Either way its version moves on as an edit's
// would.
//
// It returns the detector as restored and the one it replaced, read under
// the row lock; the second is nil when the detector was recreated.
func (p *Policies) RestoreDetector(ctx context.Context, orgID, id string, c CustomDetector, actorID string) (restored CustomDetector, replaced *CustomDetector, samplesKept bool, err error) {
	c.ID, c.OrgID, c.UpdatedBy = id, orgID, actorID
	c.MustMatch, c.MustNotMatch = nil, nil
	err = p.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		before, err := readDetector(ctx, tx, orgID, id, "FOR UPDATE")
		switch {
		case errors.Is(err, ErrDetectorNotFound):
			c = normalise(c)
			if err := c.Validate(); err != nil {
				return err
			}
			if err := insertDetector(ctx, tx, &c); err != nil {
				return err
			}
			return p.recordDetector(ctx, tx, c, revisionCreate, audit.Created(c.Recorded()), actorID)
		case err != nil:
			return err
		}
		// The name is how policies find the detector; the one stored wins.
		c.Name = before.Name
		c.MustMatch, c.MustNotMatch = before.MustMatch, before.MustNotMatch
		c = normalise(c)
		if err := c.Validate(); err != nil {
			return err
		}
		if err := policiesFit(ctx, tx, orgID, c); err != nil {
			return err
		}
		if err := updateDetector(ctx, tx, &c); err != nil {
			return err
		}
		if err := p.detectorBaseline(ctx, tx, before); err != nil {
			return err
		}
		if err := p.recordDetector(ctx, tx, c, revisionUpdate, audit.Changes(before.Recorded(), c.Recorded()), actorID); err != nil {
			return err
		}
		replaced, samplesKept = &before, true
		return nil
	})
	if err != nil {
		return CustomDetector{}, nil, false, err
	}
	p.invalidate(orgID)
	return c, replaced, samplesKept, nil
}

// policiesFit checks that every policy naming d still fits ScanCostBudget
// with d's pattern as it is about to be stored. It reads the policies and
// the other detectors they name in two statements.
func policiesFit(ctx context.Context, tx pgx.Tx, orgID string, d CustomDetector) error {
	rows, err := tx.Query(ctx, `SELECT name, detectors, max_bytes FROM dlp_policies
		WHERE organization_id = $1 AND $2 = ANY(detectors)`, orgID, d.Ref())
	if err != nil {
		return err
	}
	type user struct {
		name      string
		detectors []string
		maxBytes  int
	}
	users, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (user, error) {
		var u user
		err := row.Scan(&u.name, &u.detectors, &u.maxBytes)
		return u, err
	})
	if err != nil || len(users) == 0 {
		return err
	}
	var others []string
	for _, u := range users {
		for _, n := range u.detectors {
			if slug, ok := IsCustom(n); ok && slug != d.Name && !slices.Contains(others, slug) {
				others = append(others, slug)
			}
		}
	}
	sizes := map[string]int{}
	if len(others) > 0 {
		rows, err := tx.Query(ctx, `SELECT name, pattern, flags FROM dlp_detectors WHERE name = ANY($1)`, others)
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
		for _, n := range have {
			size, err := ProgramSize(n.pattern, n.flags)
			if err != nil {
				// A stored pattern that no longer compiles is priced at the
				// most a detector may cost, rather than at nothing.
				size = MaxProgramInsts
			}
			sizes[n.name] = size
		}
	}
	own, err := ProgramSize(d.Pattern, d.Flags)
	if err != nil {
		return err
	}
	sizes[d.Name] = own
	for _, u := range users {
		var named []int
		for _, n := range u.detectors {
			if slug, ok := IsCustom(n); ok {
				named = append(named, sizes[slug])
			}
		}
		if total, limit := scanCost(named, u.maxBytes); total > limit {
			return invalid("pattern", "with this pattern the rule %q would run custom detectors of %d instructions over %d bytes, and the most it may run is %d; simplify the pattern, or take the detector out of the rule first",
				u.name, total, effectiveMaxBytes(u.maxBytes), limit)
		}
	}
	return nil
}

func (patch DetectorPatch) apply(c CustomDetector) CustomDetector {
	if patch.Description != nil {
		c.Description = *patch.Description
	}
	if patch.Pattern != nil {
		c.Pattern = *patch.Pattern
	}
	if patch.Flags != nil {
		c.Flags = *patch.Flags
	}
	if patch.MustMatch != nil {
		c.MustMatch = slices.Clone(*patch.MustMatch)
	}
	if patch.MustNotMatch != nil {
		c.MustNotMatch = slices.Clone(*patch.MustNotMatch)
	}
	if patch.Enabled != nil {
		c.Enabled = *patch.Enabled
	}
	return c
}

// normalise gives the lists a value, so a detector reads back the way it
// was written and the diff between two of them says nothing about nil.
func normalise(c CustomDetector) CustomDetector {
	if c.MustMatch == nil {
		c.MustMatch = []string{}
	}
	if c.MustNotMatch == nil {
		c.MustNotMatch = []string{}
	}
	c.Detector = c.Ref()
	return c
}

// readDetector reads one detector inside a transaction, with lock ("" or
// "FOR UPDATE") appended.
func readDetector(ctx context.Context, tx pgx.Tx, orgID, id, lock string) (CustomDetector, error) {
	rows, err := tx.Query(ctx, `SELECT `+detectorColumns+` FROM dlp_detectors
		WHERE organization_id = $1 AND id = $2 `+lock, orgID, id)
	if err != nil {
		return CustomDetector{}, err
	}
	c, err := pgx.CollectExactlyOneRow(rows, scanDetector)
	if errors.Is(err, pgx.ErrNoRows) {
		return CustomDetector{}, ErrDetectorNotFound
	}
	return c, err
}

// insertDetector stores a new detector, within the organisation's cap.
// Two creates of the same name are told apart by the unique key.
func insertDetector(ctx context.Context, tx pgx.Tx, c *CustomDetector) error {
	// Creates in one organisation queue on this lock, as invites do, so
	// the count below is still the count when the row goes in and two
	// creates cannot both take the last place.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('dlp_detectors/' || $1))`, c.OrgID); err != nil {
		return err
	}
	var n int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM dlp_detectors WHERE organization_id = $1`, c.OrgID).Scan(&n); err != nil {
		return err
	}
	if n >= MaxCustomDetectors {
		return invalid("name", "this organisation already has %d detectors, the most it may hold; delete one first", MaxCustomDetectors)
	}
	err := tx.QueryRow(ctx, `INSERT INTO dlp_detectors
		(id, organization_id, name, description, pattern, flags, must_match, must_not_match, enabled, created_by, updated_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,NULLIF($10,''),NULLIF($11,''))
		RETURNING version, created_at, updated_at`,
		c.ID, c.OrgID, c.Name, c.Description, c.Pattern, c.Flags, c.MustMatch, c.MustNotMatch, c.Enabled,
		c.CreatedBy, c.UpdatedBy).
		Scan(&c.Version, &c.CreatedAt, &c.UpdatedAt)
	var pge *pgconn.PgError
	// 23505 is unique_violation: the (organization_id, name) key.
	if errors.As(err, &pge) && pge.Code == "23505" {
		return ErrDetectorNameTaken
	}
	return err
}

func updateDetector(ctx context.Context, tx pgx.Tx, c *CustomDetector) error {
	err := tx.QueryRow(ctx, `UPDATE dlp_detectors SET description = $3, pattern = $4, flags = $5, must_match = $6,
		must_not_match = $7, enabled = $8, updated_by = NULLIF($9,''), version = version + 1, updated_at = now()
		WHERE organization_id = $1 AND id = $2
		RETURNING version, COALESCE(created_by,''), created_at, updated_at`,
		c.OrgID, c.ID, c.Description, c.Pattern, c.Flags, c.MustMatch, c.MustNotMatch, c.Enabled, c.UpdatedBy).
		Scan(&c.Version, &c.CreatedBy, &c.CreatedAt, &c.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrDetectorNotFound
	}
	return err
}

func (p *Policies) recordDetector(ctx context.Context, tx pgx.Tx, c CustomDetector, action string, diff *audit.Diff, actorID string) error {
	if p.Revisions == nil {
		return nil
	}
	return p.Revisions.Record(ctx, tx, DetectorRevisionKind, c.ID, action, c.Recorded(), diff, actorID)
}

// detectorBaseline records a detector's state before its first recorded
// change. Every detector is created with a revision, so this only matters
// to one whose history was written while Revisions was nil.
func (p *Policies) detectorBaseline(ctx context.Context, tx pgx.Tx, before CustomDetector) error {
	if p.Revisions == nil {
		return nil
	}
	return p.Revisions.RecordBaseline(ctx, tx, DetectorRevisionKind, before.ID, before.Recorded())
}
