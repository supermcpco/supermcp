package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/supermcpco/supermcp/internal/audit"
	"github.com/supermcpco/supermcp/internal/governance"
	"github.com/supermcpco/supermcp/internal/identity"
	"github.com/supermcpco/supermcp/internal/identity/saml"
	"github.com/supermcpco/supermcp/internal/invalidation"
	"github.com/supermcpco/supermcp/internal/invoke"
	"github.com/supermcpco/supermcp/internal/mcpauth"
	"github.com/supermcpco/supermcp/internal/tenant"
)

// Background work that keeps the audit stream healthy: shipping events to
// whatever the organisation has pointed at us, dropping what is past its
// retention window, and partitioning the months to come.
//
// There is no job framework yet. What there is instead is a Postgres
// advisory lock, so that when several replicas run the same sweep only one
// of them does the work. A replica that cannot take the lock skips the
// tick rather than waiting, because the next tick is soon enough.

// leaderLock is the advisory lock id these sweeps contend for. It is a
// constant rather than a hash of a name so the value is greppable in
// pg_locks when someone is wondering who holds it.
const leaderLock int64 = 0x5DA17

type sweeps struct {
	db        *tenant.DB
	log       *slog.Logger
	retention *audit.Retention
	exporters *audit.Exporters
	// partitions creates audit_events' monthly partitions ahead of the
	// clock, and partitionsAhead receives how far ahead they reach. Like
	// the export lag, every replica measures it from shared state.
	partitions      *audit.Partitions
	partitionsAhead func(int)
	// identity, oauth and keys are the maintenance nobody asks for: spent
	// codes and dead sessions accumulate for ever without it, and a
	// signing key that is never rotated is one that lives as long as the
	// instance.
	identity *identity.Service
	oauth    *mcpauth.OAuth
	keys     *mcpauth.Keyring
	// reader anchors the audit stream: a signed checkpoint at the head,
	// so a later verification has something to compare against that the
	// database itself cannot have produced.
	reader *audit.Reader
	// saml sweeps the sign-ins nobody finished and the assertion ids that
	// could no longer be valid anyway.
	saml *saml.Service
	// approvals lapses the requests nobody answered. Every read already
	// treats a request past its deadline as expired, so this only makes
	// the stored row agree and gives the expiry a time of its own.
	approvals *governance.Approvals
	// blobs deletes the large tool results nobody collected in time. Redis
	// expires its own; the Postgres copies would otherwise stay.
	blobs *invoke.PostgresBlobStore
	// depth reports the audit queue and whatever is spooled to disk, so an
	// operator can see the writer falling behind before events start being
	// dropped, and see a backlog that a database backup would not include.
	depth func()
	// exportLag receives how far each kind of audit destination is behind.
	// Every replica measures it, not only the one that ran the last sweep:
	// the answer comes from shared state, so they agree, and a replica
	// that has not held the lock for an hour then cannot keep publishing
	// what it saw an hour ago.
	exportLag func(map[string]time.Duration)
	// invalidation hears the database say that roles, bindings, tool
	// access rules or data-loss policies changed, on any replica, and
	// drops this replica's cached copy. Every replica runs one; it is not
	// behind the leader lock.
	invalidation *invalidation.Listener
}

// start runs the sweeps until ctx is cancelled. Export runs often, because
// an exporter's job is to be close to live; retention runs rarely, because
// deleting a day early helps nobody.
func (s sweeps) start(ctx context.Context) {
	if s.invalidation != nil {
		// Run returns only once ctx is cancelled; connection failures are
		// retried inside it and logged there.
		go func() { _ = s.invalidation.Run(ctx) }()
	}
	go s.every(ctx, time.Minute, "audit-export", func(c context.Context) error {
		return s.exporters.Run(c)
	})
	go s.every(ctx, time.Hour, "audit-retention", func(c context.Context) error {
		return s.retention.Run(c)
	})
	if s.partitions != nil {
		go s.every(ctx, time.Hour, "audit-partition-maint", func(c context.Context) error {
			created, err := s.partitions.Maintain(c)
			if created > 0 {
				s.log.Info("audit partitions created", "partitions", created)
			}
			return err
		})
		if s.partitionsAhead != nil {
			go s.measurePartitions(ctx, 5*time.Minute)
		}
	}
	if s.reader != nil && s.keys != nil {
		go s.every(ctx, 10*time.Minute, "audit-anchor", func(c context.Context) error {
			return s.reader.Anchor(c, func(b []byte) (string, error) { return s.keys.SignDigest(c, b) })
		})
	}
	if s.identity != nil {
		go s.every(ctx, time.Hour, "session-prune", func(c context.Context) error {
			return s.identity.PruneSessions(c)
		})
	}
	if s.oauth != nil {
		go s.every(ctx, time.Hour, "oauth-prune", func(c context.Context) error {
			return s.oauth.PruneExpired(c)
		})
	}
	if s.keys != nil {
		go s.every(ctx, 6*time.Hour, "signing-keys", func(c context.Context) error {
			return s.keys.Maintain(c)
		})
	}
	if s.saml != nil {
		go s.every(ctx, time.Hour, "saml-sweep", s.saml.Sweep)
	}
	if s.approvals != nil {
		go s.every(ctx, 5*time.Minute, "approvals-expire", func(c context.Context) error {
			_, err := s.approvals.Sweep(c)
			return err
		})
	}
	if s.blobs != nil {
		go s.every(ctx, 5*time.Minute, "blob-sweep", func(c context.Context) error {
			_, err := s.blobs.Sweep(c)
			return err
		})
	}
	if s.exportLag != nil && s.exporters != nil {
		go s.measureExportLag(ctx, time.Minute)
	}
	if s.depth != nil {
		go func() {
			t := time.NewTicker(15 * time.Second)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					s.depth()
				}
			}
		}()
	}
}

// measureExportLag publishes the audit export lag every period until ctx
// is cancelled. A failed measurement leaves the last one standing and is
// logged; the next tick tries again.
func (s sweeps) measureExportLag(ctx context.Context, period time.Duration) {
	t := time.NewTicker(period)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c, cancel := context.WithTimeout(ctx, period/2)
			lag, err := s.exporters.Lag(c)
			cancel()
			if err != nil {
				s.log.Warn("could not measure audit export lag", "err", err)
				continue
			}
			s.exportLag(lag)
		}
	}
}

// measurePartitions publishes how many months ahead audit_events is
// partitioned, once at start and then every period until ctx is
// cancelled. A failed measurement leaves the last one standing and is
// logged; the next tick tries again.
func (s sweeps) measurePartitions(ctx context.Context, period time.Duration) {
	measure := func() {
		c, cancel := context.WithTimeout(ctx, period/2)
		defer cancel()
		months, err := s.partitions.MonthsAhead(c)
		if err != nil {
			s.log.Warn("could not measure how far ahead audit_events is partitioned", "err", err)
			return
		}
		s.partitionsAhead(months)
	}
	measure()
	t := time.NewTicker(period)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			measure()
		}
	}
}

func (s sweeps) every(ctx context.Context, period time.Duration, name string, run func(context.Context) error) {
	t := time.NewTicker(period)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.once(ctx, name, run)
		}
	}
}

// once takes the lock for the length of one run. The lock is held on a
// transaction, so a replica that dies mid-sweep releases it when its
// connection goes, rather than blocking the others until someone notices.
func (s sweeps) once(ctx context.Context, name string, run func(context.Context) error) {
	err := s.db.Bypass(ctx, name, func(tx pgx.Tx) error {
		var got bool
		if err := tx.QueryRow(ctx, "SELECT pg_try_advisory_xact_lock($1)", leaderLock).Scan(&got); err != nil {
			return err
		}
		if !got {
			return nil // another replica is on it
		}
		return run(ctx)
	})
	if err != nil {
		s.log.Error("background sweep failed", "job", name, "err", err)
	}
}
