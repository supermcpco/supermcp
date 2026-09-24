// Package dbpool keeps one connection pool per (connector, credentials)
// and hands out handles for the database engine. Pools are created lazily,
// evicted when idle, and rebuilt when a connector's DSN or credentials
// change (the key includes a hash of both).
package dbpool

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"  // mysql
	_ "github.com/jackc/pgx/v5/stdlib"  // pgx
	_ "github.com/microsoft/go-mssqldb" // sqlserver
	_ "github.com/sijms/go-ora/v2"      // oracle
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	_ "modernc.org/sqlite" // sqlite

	"github.com/supermcpco/supermcp/internal/ssrf"
)

// Dialect names a supported database.
type Dialect string

const (
	Postgres Dialect = "postgres"
	MySQL    Dialect = "mysql"
	MSSQL    Dialect = "mssql"
	Oracle   Dialect = "oracle"
	SQLite   Dialect = "sqlite"
	MongoDB  Dialect = "mongodb"
)

// Spec describes what to connect to. DSN already contains credentials
// (the engine splices them in from the decrypted auth config).
type Spec struct {
	ConnectorID string
	Dialect     Dialect
	DSN         string
	ReadOnly    bool
	MaxConns    int
	SQLiteRoot  string // sqlite files must live under this directory
}

// Handle is an open pool.
type Handle struct {
	Dialect Dialect
	SQL     *sql.DB
	Mongo   *mongo.Client
	key     string
	last    time.Time
}

// Registry owns the pools.
type Registry struct {
	dialer *ssrf.Dialer
	mu     sync.Mutex
	pools  map[string]*Handle
	max    int
}

// New builds a registry. max caps the number of open pools (LRU eviction).
func New(d *ssrf.Dialer, max int) *Registry {
	if max <= 0 {
		max = 200
	}
	return &Registry{dialer: d, pools: map[string]*Handle{}, max: max}
}

func key(s Spec) string {
	sum := sha256.Sum256([]byte(s.ConnectorID + "|" + string(s.Dialect) + "|" + s.DSN + "|" + fmt.Sprint(s.ReadOnly)))
	return hex.EncodeToString(sum[:16])
}

// Acquire returns the pool for spec, opening it on first use.
func (r *Registry) Acquire(ctx context.Context, s Spec) (*Handle, error) {
	k := key(s)
	r.mu.Lock()
	if h, ok := r.pools[k]; ok {
		h.last = time.Now()
		r.mu.Unlock()
		return h, nil
	}
	r.mu.Unlock()

	if err := r.checkHost(ctx, s); err != nil {
		return nil, err
	}
	h, err := open(ctx, s)
	if err != nil {
		return nil, err
	}
	h.key, h.last = k, time.Now()

	r.mu.Lock()
	defer r.mu.Unlock()
	if existing, ok := r.pools[k]; ok { // lost a race
		closeHandle(h) //nolint:contextcheck
		return existing, nil
	}
	if len(r.pools) >= r.max {
		r.evictOldestLocked() //nolint:contextcheck // eviction has no request context
	}
	r.pools[k] = h
	return h, nil
}

func (r *Registry) evictOldestLocked() {
	var oldestKey string
	var oldest time.Time
	for k, h := range r.pools {
		if oldestKey == "" || h.last.Before(oldest) {
			oldestKey, oldest = k, h.last
		}
	}
	if oldestKey != "" {
		closeHandle(r.pools[oldestKey])
		delete(r.pools, oldestKey)
	}
}

// Sweep closes pools idle for longer than maxIdle.
func (r *Registry) Sweep(maxIdle time.Duration) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for k, h := range r.pools {
		if time.Since(h.last) > maxIdle {
			closeHandle(h)
			delete(r.pools, k)
			n++
		}
	}
	return n
}

// Close shuts every pool.
func (r *Registry) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for k, h := range r.pools {
		closeHandle(h)
		delete(r.pools, k)
	}
}

// closeHandle runs from eviction paths that have no request context, so
// the Mongo disconnect uses a short background timeout on purpose.
func closeHandle(h *Handle) { //nolint:contextcheck
	if h.SQL != nil {
		_ = h.SQL.Close()
	}
	if h.Mongo != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = h.Mongo.Disconnect(ctx)
	}
}

// checkHost runs the SSRF policy against the DSN host before any driver
// opens a socket. sqlite has no host; its path is confined instead.
func (r *Registry) checkHost(ctx context.Context, s Spec) error {
	if s.Dialect == SQLite {
		return confineSQLite(s)
	}
	host, err := hostOf(s)
	if err != nil {
		return err
	}
	if host == "" {
		return errors.New("database DSN has no host")
	}
	if r.dialer == nil {
		return nil
	}
	_, err = r.dialer.CheckHost(ctx, host)
	return err
}

func hostOf(s Spec) (string, error) {
	dsn := s.DSN
	if s.Dialect == Oracle && !strings.Contains(dsn, "://") {
		// go-ora also accepts "user/pass@host:port/service"
		if i := strings.LastIndex(dsn, "@"); i >= 0 {
			dsn = "oracle://" + dsn[i+1:]
		}
	}
	if s.Dialect == MySQL && !strings.Contains(dsn, "://") {
		// user:pass@tcp(host:port)/db
		if i := strings.Index(dsn, "@tcp("); i >= 0 {
			rest := dsn[i+5:]
			if j := strings.Index(rest, ")"); j >= 0 {
				h, _, err := net.SplitHostPort(rest[:j])
				if err != nil {
					return rest[:j], nil
				}
				return h, nil
			}
		}
	}
	u, err := url.Parse(dsn)
	if err != nil {
		return "", fmt.Errorf("parse DSN: %w", err)
	}
	return u.Hostname(), nil
}

func confineSQLite(s Spec) error {
	if s.SQLiteRoot == "" {
		return errors.New("sqlite is disabled: no SUPERMCP_SQLITE_ROOT configured")
	}
	p := strings.TrimPrefix(strings.TrimPrefix(s.DSN, "sqlite://"), "file:")
	if i := strings.IndexByte(p, '?'); i >= 0 {
		p = p[:i]
	}
	if strings.Contains(p, "..") || !strings.HasPrefix(p, strings.TrimSuffix(s.SQLiteRoot, "/")+"/") {
		return fmt.Errorf("sqlite path %q is outside %s", p, s.SQLiteRoot)
	}
	return nil
}

func open(ctx context.Context, s Spec) (*Handle, error) {
	h := &Handle{Dialect: s.Dialect}
	var driver, dsn string
	switch s.Dialect {
	case Postgres:
		driver, dsn = "pgx", s.DSN
		if s.ReadOnly {
			dsn = appendQuery(dsn, "default_transaction_read_only=on")
		}
	case MySQL:
		driver, dsn = "mysql", strings.TrimPrefix(s.DSN, "mysql://")
		if strings.Contains(s.DSN, "://") {
			var err error
			dsn, err = mysqlDSN(s.DSN)
			if err != nil {
				return nil, err
			}
		}
	case MSSQL:
		driver, dsn = "sqlserver", strings.Replace(s.DSN, "mssql://", "sqlserver://", 1)
	case Oracle:
		driver, dsn = "oracle", s.DSN
	case SQLite:
		driver = "sqlite"
		dsn = strings.TrimPrefix(strings.TrimPrefix(s.DSN, "sqlite://"), "file:")
		if s.ReadOnly {
			dsn = appendQuery("file:"+dsn, "mode=ro")
		}
	case MongoDB:
		client, err := mongo.Connect(options.Client().ApplyURI(s.DSN).SetServerSelectionTimeout(10 * time.Second))
		if err != nil {
			return nil, err
		}
		pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		if err := client.Ping(pingCtx, nil); err != nil {
			_ = client.Disconnect(ctx)
			return nil, err
		}
		h.Mongo = client
		return h, nil
	default:
		return nil, fmt.Errorf("unsupported database dialect %q", s.Dialect)
	}
	db, err := sql.Open(driver, dsn)
	if err != nil {
		return nil, err
	}
	max := s.MaxConns
	if max <= 0 {
		max = 4
	}
	db.SetMaxOpenConns(max)
	db.SetMaxIdleConns(max)
	db.SetConnMaxIdleTime(5 * time.Minute)
	db.SetConnMaxLifetime(time.Hour)
	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := db.PingContext(pingCtx); err != nil {
		_ = db.Close()
		return nil, err
	}
	h.SQL = db
	return h, nil
}

func appendQuery(dsn, kv string) string {
	if strings.Contains(dsn, "?") {
		return dsn + "&" + kv
	}
	return dsn + "?" + kv
}

// mysqlDSN converts mysql://user:pass@host:port/db?x=y to the go-sql-driver
// form user:pass@tcp(host:port)/db?x=y.
func mysqlDSN(u string) (string, error) {
	p, err := url.Parse(u)
	if err != nil {
		return "", err
	}
	host := p.Host
	if p.Port() == "" {
		host += ":3306"
	}
	auth := ""
	if p.User != nil {
		auth = p.User.String() + "@"
	}
	out := auth + "tcp(" + host + ")" + p.Path
	if p.RawQuery != "" {
		out += "?" + p.RawQuery
	}
	return out, nil
}
