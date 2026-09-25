package invalidation

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	mathrand "math/rand/v2"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Observer receives the listener's metrics. *telemetry.Metrics satisfies
// it; a nil Observer records nothing.
type Observer interface {
	ObserveCacheInvalidation(cache, source string)
	SetCacheListenerConnected(connected bool)
}

// Execer runs one statement. *pgxpool.Pool and *pgx.Conn satisfy it.
type Execer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// Options configure a Listener.
type Options struct {
	// URL is the Postgres connection the listener holds open. It must reach
	// Postgres directly: LISTEN through a transaction-pooling proxy such as
	// PgBouncer in transaction mode registers on whichever server
	// connection ran it and is then never delivered. The listener proves
	// delivery with a probe and refuses to report itself connected when it
	// does not arrive.
	URL string
	// Prober sends the liveness probe. It should be a different session
	// from the listener's own (the maintenance pool): a probe sent on the
	// listening connection itself comes back even through a
	// transaction-pooling proxy, because the proxy forwards it with the
	// reply, and so proves nothing about notifications other sessions
	// send. Nil sends it on the listening connection.
	Prober Execer
	// ApplicationName names the session in pg_stat_activity. Default
	// "supermcp-listener".
	ApplicationName string
	Log             *slog.Logger
	// Observer receives the invalidation counter and the connected gauge.
	Observer Observer
	// HealthInterval is how long the connection may stay silent before the
	// listener sends itself a probe. A half-open TCP connection delivers
	// nothing and reports no error, so silence has to be tested. Default
	// 30s.
	HealthInterval time.Duration
	// ProbeTimeout is how long a probe may take to come back. Default 5s.
	ProbeTimeout time.Duration
	// MinBackoff and MaxBackoff bound the wait between reconnects.
	// Defaults 500ms and 30s.
	MinBackoff time.Duration
	MaxBackoff time.Duration
}

// Listener holds one LISTEN connection and invalidates the registered
// caches on each notification.
//
// Lifecycle: the caller starts Run on its own goroutine and cancels its
// context to stop it. Run never returns while the context is live; every
// connection error is logged, the connected gauge drops to 0, and it
// reconnects with capped exponential backoff. Each successful (re)connect
// flushes every registered cache, because notifications sent while it was
// away are gone.
type Listener struct {
	opts Options
	log  *slog.Logger

	// mu guards caches, which Register writes and the Run goroutine reads.
	mu     sync.RWMutex
	caches map[Kind][]Cache

	connected atomic.Bool
}

// errProbeLost is returned when the listener's own notification does not
// come back: the connection is not delivering, whatever it claims.
var errProbeLost = errors.New("probe notification not delivered: the connection does not receive notifications (a transaction-pooling proxy, or a dead connection)")

// NewListener builds a listener. Register caches before or after Run; a
// cache registered late gets notifications from then on.
func NewListener(opts Options) *Listener {
	if opts.ApplicationName == "" {
		opts.ApplicationName = "supermcp-listener"
	}
	if opts.HealthInterval <= 0 {
		opts.HealthInterval = 30 * time.Second
	}
	if opts.ProbeTimeout <= 0 {
		opts.ProbeTimeout = 5 * time.Second
	}
	if opts.MinBackoff <= 0 {
		opts.MinBackoff = 500 * time.Millisecond
	}
	if opts.MaxBackoff < opts.MinBackoff {
		opts.MaxBackoff = max(30*time.Second, opts.MinBackoff)
	}
	log := opts.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Listener{opts: opts, log: log, caches: map[Kind][]Cache{}}
}

// Register adds a cache to be invalidated for kind.
func (l *Listener) Register(kind Kind, c Cache) {
	if c == nil {
		return
	}
	l.mu.Lock()
	l.caches[kind] = append(l.caches[kind], c)
	l.mu.Unlock()
}

// Connected reports whether the listener holds a connection that has
// proved it delivers notifications.
func (l *Listener) Connected() bool { return l.connected.Load() }

// Run listens until ctx is cancelled, reconnecting as needed. It returns
// nil once ctx is done.
func (l *Listener) Run(ctx context.Context) error {
	l.setConnected(false)
	backoff := l.opts.MinBackoff
	for {
		wasUp, err := l.session(ctx)
		l.setConnected(false)
		if ctx.Err() != nil {
			return nil
		}
		if wasUp {
			backoff = l.opts.MinBackoff
		}
		wait := jitter(backoff)
		l.log.Warn("cache invalidation listener disconnected; caches fall back to their time-to-live until it reconnects",
			"err", err, "retry_in", wait)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
		backoff = min(backoff*2, l.opts.MaxBackoff)
	}
}

// session runs one connection until it fails. wasUp reports whether the
// connection got as far as delivering a probe, which resets the backoff.
func (l *Listener) session(ctx context.Context) (wasUp bool, err error) {
	conn, err := l.connect(ctx)
	if err != nil {
		return false, err
	}
	defer func() {
		// The session's context is usually the one that ended it, so the
		// close gets a short one of its own.
		closeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer cancel()
		_ = conn.Close(closeCtx)
	}()

	if _, err := conn.Exec(ctx, "LISTEN "+pgx.Identifier{Channel}.Sanitize()); err != nil {
		return false, fmt.Errorf("listen: %w", err)
	}
	// Anything committed from here on is delivered; anything before it is
	// covered by the flush below. The probe comes first so that a
	// connection that cannot deliver is never reported as connected.
	if err := l.probe(ctx, conn); err != nil {
		return false, err
	}
	l.flush(SourceReconnect)
	l.setConnected(true)

	for {
		waitCtx, cancel := context.WithTimeout(ctx, l.opts.HealthInterval)
		n, err := conn.WaitForNotification(waitCtx)
		cancel()
		switch {
		case err == nil:
			l.dispatch(n.Payload, "")
		case ctx.Err() != nil:
			return true, ctx.Err()
		case pgconn.Timeout(err):
			if err := l.probe(ctx, conn); err != nil {
				return true, err
			}
		default:
			return true, fmt.Errorf("wait for notification: %w", err)
		}
	}
}

func (l *Listener) connect(ctx context.Context) (*pgx.Conn, error) {
	cfg, err := pgx.ParseConfig(l.opts.URL)
	if err != nil {
		return nil, fmt.Errorf("cache listener: %w", err)
	}
	cfg.RuntimeParams["application_name"] = l.opts.ApplicationName
	dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, err := pgx.ConnectConfig(dialCtx, cfg)
	if err != nil {
		return nil, fmt.Errorf("cache listener: connect: %w", err)
	}
	return conn, nil
}

// probe sends the listener a notification of its own and waits for it,
// handling any real notification that arrives in the meantime.
func (l *Listener) probe(ctx context.Context, conn *pgx.Conn) error {
	nonce, err := newNonce()
	if err != nil {
		return err
	}
	probeCtx, cancel := context.WithTimeout(ctx, l.opts.ProbeTimeout)
	defer cancel()
	var sender Execer = conn
	if l.opts.Prober != nil {
		sender = l.opts.Prober
	}
	if _, err := sender.Exec(probeCtx, "SELECT pg_notify($1, $2)", Channel, probeKind+":"+nonce); err != nil {
		return fmt.Errorf("send probe: %w", err)
	}
	for {
		n, err := conn.WaitForNotification(probeCtx)
		if err != nil {
			if ctx.Err() == nil && pgconn.Timeout(err) {
				return errProbeLost
			}
			return fmt.Errorf("wait for probe: %w", err)
		}
		if l.dispatch(n.Payload, nonce) {
			return nil
		}
	}
}

// dispatch applies one payload. It reports whether the payload was the
// probe carrying nonce.
func (l *Listener) dispatch(payload, nonce string) bool {
	m := parse(payload)
	l.log.Debug("cache invalidation notification", "payload", payload)
	if m.probe {
		return nonce != "" && m.orgID == nonce
	}
	if m.kind != KindAuthz && m.kind != KindDLP {
		// A kind this build does not know, or a payload it cannot read:
		// drop everything rather than guess.
		l.log.Warn("cache invalidation payload not understood; flushing every cache", "payload_kind", string(m.kind))
		l.flush(SourceNotify)
		return false
	}
	l.mu.RLock()
	caches := l.caches[m.kind]
	l.mu.RUnlock()
	if len(caches) == 0 {
		return false
	}
	for _, c := range caches {
		if m.all {
			c.InvalidateAll()
		} else {
			c.InvalidateOrg(m.orgID)
		}
	}
	l.observe(m.kind, SourceNotify)
	return false
}

// flush drops every registered cache's entries.
func (l *Listener) flush(src Source) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	for kind, caches := range l.caches {
		for _, c := range caches {
			c.InvalidateAll()
		}
		l.observe(kind, src)
	}
}

func (l *Listener) observe(kind Kind, src Source) {
	if l.opts.Observer != nil {
		l.opts.Observer.ObserveCacheInvalidation(string(kind), string(src))
	}
}

func (l *Listener) setConnected(up bool) {
	was := l.connected.Swap(up)
	if l.opts.Observer != nil {
		l.opts.Observer.SetCacheListenerConnected(up)
	}
	if up && !was {
		l.log.Info("cache invalidation listener connected", "channel", Channel)
	}
}

func newNonce() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("probe nonce: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// jitter spreads reconnects over [d/2, d) so replicas that lost the
// database together do not return together.
func jitter(d time.Duration) time.Duration {
	half := d / 2
	if half <= 0 {
		return d
	}
	return half + mathrand.N(half) //nolint:gosec // spreading retries, not a secret
}
