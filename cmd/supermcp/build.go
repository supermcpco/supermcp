package main

import (
	"context"
	"log/slog"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/supermcpco/supermcp/internal/audit"
	"github.com/supermcpco/supermcp/internal/authz"
	"github.com/supermcpco/supermcp/internal/catalog"
	"github.com/supermcpco/supermcp/internal/config"
	"github.com/supermcpco/supermcp/internal/connector"
	"github.com/supermcpco/supermcp/internal/dbpool"
	"github.com/supermcpco/supermcp/internal/dlp"
	"github.com/supermcpco/supermcp/internal/governance"
	"github.com/supermcpco/supermcp/internal/hardening"
	"github.com/supermcpco/supermcp/internal/httpapi"
	"github.com/supermcpco/supermcp/internal/httpclient"
	"github.com/supermcpco/supermcp/internal/identity"
	"github.com/supermcpco/supermcp/internal/identity/saml"
	"github.com/supermcpco/supermcp/internal/identity/sso"
	"github.com/supermcpco/supermcp/internal/invalidation"
	"github.com/supermcpco/supermcp/internal/invoke"
	mcpendpoint "github.com/supermcpco/supermcp/internal/mcp"
	"github.com/supermcpco/supermcp/internal/mcpauth"
	"github.com/supermcpco/supermcp/internal/mcpserver"
	"github.com/supermcpco/supermcp/internal/scim"
	"github.com/supermcpco/supermcp/internal/secrets"
	"github.com/supermcpco/supermcp/internal/ssrf"
	"github.com/supermcpco/supermcp/internal/store"
	"github.com/supermcpco/supermcp/internal/telemetry"
	"github.com/supermcpco/supermcp/internal/tenant"
)

// newID mints identifiers. UUIDv7 keeps rows roughly time-ordered, which
// helps index locality on the invocation table.
func newID() string {
	id, err := uuid.NewV7()
	if err != nil {
		return uuid.NewString()
	}
	return id.String()
}

// build wires the services. The returned cleanup closes pools that outlive
// individual requests.
func build(ctx context.Context, cfg *config.Config, log *slog.Logger, st *store.Store, cat *catalog.Catalog) (httpapi.Deps, sweeps, func(), error) {
	db := &tenant.DB{App: st.App, Maint: st.Maint, Log: log}

	metrics := telemetry.NewMetrics(telemetry.MetricsOptions{
		PerTool: cfg.Metrics.PerTool, PerToolCap: cfg.Metrics.PerToolCap, GoCollectors: true,
	})
	// A saturated pool looks like everything being slow at once; the
	// pool's own numbers are what say it is the pool.
	metrics.WatchDBPool(telemetry.PoolApp, poolStats(st.App))
	metrics.WatchDBPool(telemetry.PoolMaint, poolStats(st.Maint))

	// Master key selection happens once, here, so a misconfigured provider
	// is a boot failure and never a silent downgrade to a weaker one. The
	// context bounds the provider's own start-up: building the AWS client
	// resolves credentials, which can mean a call to the metadata service.
	keks, err := secrets.KEKFromEnv(ctx, os.Getenv)
	if err != nil {
		return httpapi.Deps{}, sweeps{}, nil, err
	}
	// The decrypt-only keys are what let a rotation roll without a window:
	// a pod on the new master key still opens what the old one wrapped.
	// Every master key is observed, so a KMS that has stopped answering
	// shows as itself rather than as a scatter of failing tool calls.
	observeKEK := secrets.KEKObserver(metrics.ObserveKEK)
	previous := make([]secrets.KEK, 0, len(keks.Previous))
	for _, k := range keks.Previous {
		previous = append(previous, secrets.Observed(k, secrets.KeyPrevious, observeKEK))
	}
	sealer := secrets.New(secrets.Observed(keks.Active, secrets.KeyActive, observeKEK), &store.KeyStore{DB: db}, previous...)

	policy := ssrf.FromEnv(os.Getenv)
	if cfg.Dev {
		// Local development talks to services on the host.
		policy.AllowLoopback = true
	}
	dialer := ssrf.NewDialer(policy)
	clients := httpclient.NewFactory(dialer)
	pools := dbpool.New(dialer, 200)

	// The audit writer appends as the maintenance role, so a bug in a
	// request handler cannot forge or rewrite history.
	// The writer appends from its own goroutine, which outlives every
	// request it records, so it holds a context of its own.
	auditor := audit.NewWriter(db, log, audit.OptionsFromEnv(os.Getenv)) //nolint:contextcheck // the writer owns its lifetime
	policies := audit.NewPolicies(db)

	// A trace says where inside one call the time went, which metrics
	// cannot. Off unless a collector is named.
	tracer := telemetry.NewTracer(ctx, telemetry.TraceOptions{
		Endpoint: cfg.Tracing.Endpoint, Sample: cfg.Tracing.Sample,
		Service: "supermcp", Version: cfg.Version, Log: log,
	})

	var limiter *hardening.Limiter
	if cfg.RateLimit.Enabled {
		l, err := hardening.New(ctx, hardening.Options{
			RedisURL: cfg.RedisURL, ExpectedReplicas: cfg.RateLimit.ExpectedReplicas, MaxKeys: cfg.RateLimit.MaxKeys,
			OnDegraded: func(m hardening.Mode, err error) {
				metrics.SetRateLimitDegraded(m != hardening.ModeRedis)
				if m == hardening.ModeRedis {
					log.Info("rate limiter recovered", "mode", m)
					return
				}
				// Falling back divides the budget per replica rather than
				// letting traffic through, so this is a warning and not an
				// outage.
				log.Warn("rate limiter degraded to per-replica budgets", "mode", m, "err", err)
			},
		})
		if err != nil {
			return httpapi.Deps{}, sweeps{}, nil, err
		}
		limiter = l
		metrics.SetRateLimitDegraded(limiter.Degraded())
	}

	// The breaker already knows the connector it was built for; this is the
	// only wire between it and the gauge.
	clients.OnBreakerState = func(connectorID string, st httpclient.BreakerState) {
		metrics.SetBreakerState(connectorID, telemetry.BreakerState(st))
	}

	az := authz.New(db)
	az.OnInvalidate = func(source string) { metrics.ObserveCacheInvalidation(telemetry.CacheAuthz, source) }
	ids := identity.New(db, identity.Config{OpenRegistration: cfg.OpenRegistration}, az, newID)
	keys := mcpauth.New(db, newID)
	keyring := mcpauth.NewKeyring(db, sealer, newID)
	keyring.Log = log
	oauth := mcpauth.NewOAuth(db, keyring, cfg.PublicURL.String(), mcpauth.DCRMode(cfg.DCRMode), newID)
	// Service accounts use the client credentials grant, so the
	// authorization server has to be able to authenticate them.
	oauth.Accounts = ids
	// A token from a browser consent names its session, and ending the
	// session refuses the token.
	oauth.Sessions = ids
	// Provider calls go through the SSRF-guarded client: an issuer URL is
	// administrator-supplied, and must not be able to reach inside.
	idpClient := httpclient.New(dialer, "identity-providers", httpclient.DefaultPolicy())
	sso := sso.New(db, sealer, idpClient, newID, cfg.PublicURL)
	provisioning := scim.New(db, ids, az, newID)
	provisioning.Audit = auditor
	// The exporter dials customer-supplied URLs, so it uses the guarded
	// client for the same reason the identity providers do.
	exportClient := httpclient.New(dialer, "audit-exporters", httpclient.DefaultPolicy())
	importClient := httpclient.New(dialer, "openapi-import", httpclient.DefaultPolicy())
	revisions := governance.New(db, newID)
	conns := connector.New(db, sealer, newID)
	conns.Revisions = revisions
	servers := mcpserver.New(db, conns, newID)
	servers.Revisions = revisions
	// The sign-in providers are versioned too: who may sign in, and how,
	// is worth being able to put back.
	sso.Revisions = revisions
	// Read-only tool results are remembered for as long as the adapter said
	// they stay true. Redis when there is one, per replica otherwise.
	responses, err := invoke.NewCache(ctx, invoke.CacheOptions{
		RedisURL: cfg.RedisURL, Log: log,
		OnDegraded: func(m invoke.CacheMode, err error) {
			if m == invoke.CacheModeRedis {
				log.Info("response cache recovered", "mode", m)
				return
			}
			log.Warn("response cache degraded to per-replica entries", "mode", m, "err", err)
		},
	})
	if err != nil {
		return httpapi.Deps{}, sweeps{}, nil, err
	}
	// Binary results too large to embed are held here and fetched back over
	// /api/v1/blobs/{id} by the principal that caused them. The fetch can
	// land on any replica, so the store is shared: Redis when there is one,
	// with Postgres behind it, and Postgres alone otherwise.
	pgBlobs := &invoke.PostgresBlobStore{DB: db, BaseURL: cfg.PublicURL.String()}
	var blobs invoke.BlobStore = pgBlobs
	var redisBlobs *invoke.RedisBlobStore
	if cfg.RedisURL != "" {
		if redisBlobs, err = invoke.NewRedisBlobStore(cfg.RedisURL, cfg.PublicURL.String(), 0); err != nil {
			return httpapi.Deps{}, sweeps{}, nil, err
		}
		blobs = &invoke.FallbackBlobStore{Primary: redisBlobs, Secondary: pgBlobs, Log: log}
	}
	// Sealed under the workspace's data key wherever it lands: a result is
	// upstream data, and it is the only thing that would otherwise sit at
	// rest in the clear.
	blobs = &invoke.SealedBlobStore{Inner: blobs, Sealer: sealer}
	// Governance sits between the authorisation decision and the engine:
	// a data-loss rule may mask or refuse what crosses, and an approval
	// rule may hold a call until a person agrees to it.
	dlpPolicies := dlp.NewPolicies(db, newID)
	dlpPolicies.Revisions = revisions
	dlpPolicies.OnInvalidate = func(source string) { metrics.ObserveCacheInvalidation(telemetry.CacheDLP, source) }
	// Both caches above are per replica. The database notifies every
	// replica when what they hold changes; this holds the connection that
	// hears it. It is a session of its own on the maintenance URL, which
	// is the one documented to reach Postgres directly: LISTEN does not
	// survive a transaction-pooling proxy.
	listener := invalidation.NewListener(invalidation.Options{
		URL: cfg.MaintDatabaseURL, Prober: st.Maint, Log: log, Observer: metrics,
	})
	listener.Register(invalidation.KindAuthz, az)
	listener.Register(invalidation.KindDLP, dlpPolicies)
	approvals := governance.NewApprovals(db, sealer, newID)
	approvals.Audit = auditor
	exec := invoke.New(invoke.Deps{DB: db, Connectors: conns, Clients: clients, Pools: pools,
		SQLiteRoot: os.Getenv("SUPERMCP_SQLITE_ROOT"), Log: log, NewID: newID,
		Audit: auditor, Policies: policies, Metrics: metrics,
		DLP: dlpPolicies, Approvals: approvals, Tracer: tracer,
		Cache: responses, Content: &invoke.Content{Blobs: blobs, Log: log}})
	endpoint := mcpendpoint.New(mcpendpoint.Deps{Servers: servers, Authz: az, Executor: exec, Log: log,
		Version: cfg.Version, JSONResponse: cfg.MCPJSONResponse, PublicURL: cfg.PublicURL.String(),
		Metrics: metrics, Tracer: tracer})

	// SAML shares the guarded client with the OIDC path: an identity
	// provider's metadata URL comes from whoever configured it.
	samlSvc := saml.New(db, sealer, importClient, newID, cfg.PublicURL)
	samlSvc.Revisions = revisions

	retention := audit.NewRetention(db, log)
	deps := httpapi.Deps{
		Config: cfg, Log: log, Store: st, Catalog: cat, DB: db,
		Identity: ids, Authz: az, Keys: keys, Connectors: conns, Servers: servers, MCP: endpoint, OAuth: oauth,
		Executor: exec,
		SSO:      sso, SCIM: provisioning, SAML: samlSvc,
		Revisions: revisions, DLP: dlpPolicies,
		Audit: auditor, AuditReader: &audit.Reader{DB: db, VerifyAnchor: keyring.VerifyDigest}, AuditPolicies: policies,
		AuditRetention: retention,
		Limiter:        limiter, Budgets: cfg.RateLimit.Budgets, Metrics: metrics, Blobs: blobs, ImportFetch: importClient,
		OpenRegistration: cfg.OpenRegistration,
	}
	jobs := sweeps{db: db, log: log, invalidation: listener,
		identity: ids, oauth: oauth, keys: keyring, saml: samlSvc, reader: &audit.Reader{DB: db},
		approvals: approvals, blobs: pgBlobs,
		retention: retention,
		// Syslog destinations open a socket of their own, so they dial
		// through the guard the HTTP destinations already go through.
		exporters: audit.NewExporters(db, sealer, exportClient, log).WithDial(dialer.DialContext),
		exportLag: metrics.SetAuditExportLag,
		depth: func() {
			metrics.SetAuditQueueDepth(auditor.QueueDepth())
			metrics.SetAuditSpoolDepth(auditor.SpoolDepth())
			metrics.SetAuditDroppedTotal(auditor.DroppedTotal())
		}}
	// Dynamic client registration is rate limited by the same budget the
	// rest of the surface uses.
	if limiter != nil {
		oauth.Clients = limiter.Bounded(cfg.RateLimit.Budgets.DCR)
	}
	return deps, jobs, func() { //nolint:contextcheck // shutdown, after every request context is gone
		// Draining the audit queue before the pools close is what keeps the
		// last events of a shutdown from being lost.
		// The trace of the request that broke everything is the one worth
		// keeping, so what has not been sent is flushed before the pools go.
		flush, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := tracer.Shutdown(flush); err != nil {
			log.Warn("traces were not flushed on the way out", "err", err)
		}
		auditor.Close()
		if limiter != nil {
			_ = limiter.Close()
		}
		_ = responses.Close()
		if redisBlobs != nil {
			_ = redisBlobs.Close()
		}
		pools.Close()
	}, nil
}

// poolStats copies a pgx pool's statistics into the shape telemetry
// publishes, which keeps the driver out of the telemetry package.
func poolStats(p *pgxpool.Pool) func() telemetry.DBPoolStats {
	return func() telemetry.DBPoolStats {
		s := p.Stat()
		return telemetry.DBPoolStats{
			Acquired: s.AcquiredConns(), Idle: s.IdleConns(), Total: s.TotalConns(), Max: s.MaxConns(),
			Acquires: s.AcquireCount(), EmptyAcquires: s.EmptyAcquireCount(), EmptyAcquireWait: s.EmptyAcquireWaitTime(),
		}
	}
}
