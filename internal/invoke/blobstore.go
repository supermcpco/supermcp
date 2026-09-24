package invoke

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/redis/go-redis/v9"

	"github.com/supermcpco/supermcp/internal/tenant"
)

// A blob link is fetched by whoever the MCP client talks to next, and
// behind a load balancer that is any replica. So the stores here are
// shared: Redis when there is one, Postgres otherwise, and Postgres again
// when Redis fails. MemoryBlobStore stays for tests and a single process.

func blobURL(base, id string) string { return strings.TrimSuffix(base, "/") + "/api/v1/blobs/" + id }

// PostgresBlobStore keeps blobs in tool_blobs, under the workspace's
// row-level security. Every replica sees every blob.
type PostgresBlobStore struct {
	DB      *tenant.DB
	BaseURL string
	TTL     time.Duration
	Now     func() time.Time
}

func (s *PostgresBlobStore) ttl() time.Duration {
	if s.TTL <= 0 {
		return defaultBlobTTL
	}
	return s.TTL
}

func (s *PostgresBlobStore) now() time.Time {
	if s.Now == nil {
		return time.Now()
	}
	return s.Now()
}

// Put stores b until its TTL runs out.
func (s *PostgresBlobStore) Put(ctx context.Context, b Blob) (BlobRef, error) {
	if b.Owner.Zero() {
		return BlobRef{}, errors.New("blob needs an owner")
	}
	id, err := blobID()
	if err != nil {
		return BlobRef{}, err
	}
	expires := s.now().Add(s.ttl())
	err = s.DB.Tx(tenant.WithOrg(ctx, b.Owner.OrgID), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO tool_blobs (id, organization_id, principal_id, media_type, name, data, expires_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7)`, id, b.Owner.OrgID, b.Owner.PrincipalID, b.MediaType, b.Name, b.Data, expires)
		return err
	})
	if err != nil {
		return BlobRef{}, fmt.Errorf("store blob: %w", err)
	}
	return BlobRef{ID: id, URL: blobURL(s.BaseURL, id), ExpiresAt: expires}, nil
}

// Get returns the blob when it exists, has not expired and belongs to
// owner. The owner is part of the query, and row-level security scopes it
// to the owner's workspace as well.
func (s *PostgresBlobStore) Get(ctx context.Context, id string, owner BlobOwner) (Blob, bool, error) {
	if owner.Zero() {
		return Blob{}, false, nil
	}
	b := Blob{Owner: owner}
	err := s.DB.Tx(tenant.WithOrg(ctx, owner.OrgID), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT media_type, name, data, expires_at FROM tool_blobs
			WHERE id = $1 AND organization_id = $2 AND principal_id = $3 AND expires_at > $4`,
			id, owner.OrgID, owner.PrincipalID, s.now()).Scan(&b.MediaType, &b.Name, &b.Data, &b.ExpiresAt)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return Blob{}, false, nil
	}
	if err != nil {
		return Blob{}, false, err
	}
	return b, true, nil
}

// Sweep deletes expired blobs across every workspace.
func (s *PostgresBlobStore) Sweep(ctx context.Context) (int64, error) {
	var n int64
	err := s.DB.Bypass(ctx, "blob-sweep", func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM tool_blobs WHERE expires_at <= $1`, s.now())
		n = tag.RowsAffected()
		return err
	})
	return n, err
}

// RedisBlobStore keeps blobs in Redis, where the TTL does the sweeping.
type RedisBlobStore struct {
	client  *redis.Client
	prefix  string
	baseURL string
	ttl     time.Duration
}

// NewRedisBlobStore connects to Redis. Its timeouts are longer than the
// response cache's: a blob can be tens of megabytes, and a store that
// gives up on it half-written only sends it to the fallback.
func NewRedisBlobStore(redisURL, baseURL string, ttl time.Duration) (*RedisBlobStore, error) {
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("parse redis url: %w", err)
	}
	opts.DialTimeout = 2 * time.Second
	opts.ReadTimeout = 5 * time.Second
	opts.WriteTimeout = 5 * time.Second
	opts.MaxRetries = 1
	if ttl <= 0 {
		ttl = defaultBlobTTL
	}
	return &RedisBlobStore{client: redis.NewClient(opts), prefix: "supermcp:blob:", baseURL: baseURL, ttl: ttl}, nil
}

// Close releases the connection pool.
func (s *RedisBlobStore) Close() error { return s.client.Close() }

// Put stores b as a hash that expires with the blob.
func (s *RedisBlobStore) Put(ctx context.Context, b Blob) (BlobRef, error) {
	if b.Owner.Zero() {
		return BlobRef{}, errors.New("blob needs an owner")
	}
	id, err := blobID()
	if err != nil {
		return BlobRef{}, err
	}
	expires := time.Now().Add(s.ttl)
	key := s.prefix + id
	_, err = s.client.TxPipelined(ctx, func(p redis.Pipeliner) error {
		p.HSet(ctx, key, "org", b.Owner.OrgID, "principal", b.Owner.PrincipalID,
			"type", b.MediaType, "name", b.Name, "data", b.Data, "expires", expires.UnixMilli())
		p.PExpireAt(ctx, key, expires)
		return nil
	})
	if err != nil {
		return BlobRef{}, fmt.Errorf("store blob: %w", err)
	}
	return BlobRef{ID: id, URL: blobURL(s.baseURL, id), ExpiresAt: expires}, nil
}

// Get returns the blob when it exists and belongs to owner.
func (s *RedisBlobStore) Get(ctx context.Context, id string, owner BlobOwner) (Blob, bool, error) {
	if owner.Zero() {
		return Blob{}, false, nil
	}
	v, err := s.client.HGetAll(ctx, s.prefix+id).Result()
	if err != nil {
		return Blob{}, false, err
	}
	if len(v) == 0 {
		return Blob{}, false, nil
	}
	stored := BlobOwner{OrgID: v["org"], PrincipalID: v["principal"]}
	if !stored.Equal(owner) {
		return Blob{}, false, nil
	}
	var ms int64
	_, _ = fmt.Sscan(v["expires"], &ms)
	return Blob{Owner: stored, MediaType: v["type"], Name: v["name"], Data: []byte(v["data"]),
		ExpiresAt: time.UnixMilli(ms)}, true, nil
}

// FallbackBlobStore writes to Primary and, when that fails, to Secondary,
// and reads from both. A Redis that goes away costs a slower store rather
// than a result the caller cannot collect.
type FallbackBlobStore struct {
	Primary, Secondary BlobStore
	Log                *slog.Logger
}

// Put tries the primary store first.
func (s *FallbackBlobStore) Put(ctx context.Context, b Blob) (BlobRef, error) {
	ref, err := s.Primary.Put(ctx, b)
	if err == nil {
		return ref, nil
	}
	if s.Log != nil {
		s.Log.Warn("blob store falling back", "err", err)
	}
	return s.Secondary.Put(ctx, b)
}

// Get looks in the primary store, then the secondary: a blob written
// while the primary was down lives only in the secondary.
func (s *FallbackBlobStore) Get(ctx context.Context, id string, owner BlobOwner) (Blob, bool, error) {
	b, ok, err := s.Primary.Get(ctx, id, owner)
	if ok {
		return b, true, nil
	}
	b2, ok2, err2 := s.Secondary.Get(ctx, id, owner)
	if ok2 || err2 != nil {
		return b2, ok2, err2
	}
	// Neither has it. A blob that was only in an unreachable primary is as
	// gone as an expired one, and the caller answers both with a 404; an
	// error here would turn a Redis outage into a 500 on every old link.
	if err != nil && s.Log != nil {
		s.Log.Warn("blob store primary unavailable on read", "err", err)
	}
	return Blob{}, false, nil
}
