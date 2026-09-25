package compliance

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/supermcpco/supermcp/internal/config"
)

// SnapshotOptions tunes the configuration snapshot.
type SnapshotOptions struct {
	// Cfg is the process configuration as this binary validated it. The
	// snapshot reports these rather than re-deriving defaults, so it can
	// never disagree with what the gateway would actually do.
	Cfg *config.Config
	// Environ is the environment to read, in os.Environ form. Nil means
	// the process's own.
	Environ []string
}

// Snapshot is the shape of an instance: what decides its behaviour, with
// every secret replaced by a digest of itself, so it can be handed to an
// assessor without handing them the instance.
type Snapshot struct {
	GeneratedAt time.Time `json:"generatedAt"`
	Instance    Instance  `json:"instance"`
	// Effective is what this binary will act on, after defaults.
	Effective []Setting `json:"effective"`
	// Environment is what an operator actually set. A variable this binary
	// does not read is reported too: a setting that looks applied and is
	// not is the most expensive kind of misconfiguration.
	Environment []Setting     `json:"environment"`
	Site        []Setting     `json:"siteSettings"`
	Workspaces  []OrgSettings `json:"workspaceSettings"`
	Counts      []Count       `json:"counts"`
	Limits      []string      `json:"limits"`
}

// Instance identifies which installation the snapshot describes.
type Instance struct {
	ID            string    `json:"id"`
	CreatedAt     time.Time `json:"createdAt"`
	SchemaVersion int64     `json:"schemaVersion"`
	BinaryVersion string    `json:"binaryVersion"`
}

// Setting is one thing that decides behaviour.
type Setting struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	// Source says where the value came from: "set" for something an
	// operator supplied, "default" for what the binary chose, "database"
	// for a row.
	Source string `json:"source"`
	// Redacted is true when Value is a digest rather than the value.
	Redacted bool `json:"redacted,omitempty"`
	// Note carries a remark about this setting, such as that the binary
	// does not read it.
	Note string `json:"note,omitempty"`
}

// OrgSettings is one workspace's stored settings.
type OrgSettings struct {
	OrgID    string    `json:"orgId"`
	Slug     string    `json:"slug"`
	Settings []Setting `json:"settings"`
}

// Count is one population of the instance, which is the other half of its
// shape: an assessor reads differently a gateway with two connectors and
// one with four hundred.
type Count struct {
	Of string `json:"of"`
	N  int64  `json:"n"`
}

// known lists the environment variables this binary reads. It is names
// only, deliberately: a list of defaults here would be a second copy of
// the ones in config and secrets, and the day they disagreed the snapshot
// would be the one lying. A variable missing from this list is reported
// as unread rather than hidden, so the list failing behind costs a
// question and never a silent omission.
var known = map[string]bool{
	"DATABASE_URL": true, "REDIS_URL": true,
	"ENCRYPTION_KEK": true, "ENCRYPTION_KEK_FILE": true,
	"SUPERMCP_LISTEN": true, "SUPERMCP_ADMIN_LISTEN": true, "SUPERMCP_PUBLIC_URL": true,
	"SUPERMCP_DATABASE_URL": true, "SUPERMCP_MAINT_DATABASE_URL": true, "SUPERMCP_REDIS_URL": true,
	"SUPERMCP_LOG_LEVEL": true, "SUPERMCP_LOG_FORMAT": true, "SUPERMCP_DEV": true,
	"SUPERMCP_OPEN_REGISTRATION": true, "SUPERMCP_DCR_MODE": true, "SUPERMCP_MCP_RESPONSE_MODE": true,
	"SUPERMCP_SQLITE_ROOT": true, "SUPERMCP_MIGRATE_ON_START": true, "SUPERMCP_SHUTDOWN_TIMEOUT": true,
	"SUPERMCP_AUTH_FRESH_WINDOW": true,
	"SUPERMCP_RATELIMIT_ENABLED": true, "SUPERMCP_RATELIMIT_SIGNIN": true, "SUPERMCP_RATELIMIT_REGISTER": true,
	"SUPERMCP_RATELIMIT_INVITE": true, "SUPERMCP_RATELIMIT_DCR": true, "SUPERMCP_RATELIMIT_TOOL_CALL": true,
	"SUPERMCP_RATELIMIT_ANALYTICS": true, "SUPERMCP_RATELIMIT_API": true, "SUPERMCP_RATELIMIT_MAX_KEYS": true,
	"SUPERMCP_EXPECTED_REPLICAS": true, "SUPERMCP_METRICS_PER_TOOL": true, "SUPERMCP_METRICS_PER_TOOL_CAP": true,
	"SUPERMCP_KEK_PROVIDER": true, "SUPERMCP_KEK_PREVIOUS": true,
	"SUPERMCP_KMS_KEY_ID": true, "SUPERMCP_KMS_REGION": true, "SUPERMCP_KMS_DEPLOYMENT": true,
	"SUPERMCP_KMS_TIMEOUT": true,
	"SUPERMCP_INSTANCE_ID": true, "SUPERMCP_AUDIT_ON_UNAVAILABLE": true, "SUPERMCP_AUDIT_SPOOL_DIR": true,
	"SUPERMCP_AUDIT_SPOOL_MAX_BYTES": true, "SUPERMCP_AUDIT_SPOOL_ORPHAN_AGE": true,
}

// ConfigSnapshot builds the snapshot.
func ConfigSnapshot(ctx context.Context, d Deps, opts SnapshotOptions) (*Snapshot, error) {
	s := &Snapshot{
		GeneratedAt: d.now(),
		Effective:   effectiveSettings(opts.Cfg),
		Environment: environment(opts.Environ),
		Site:        []Setting{},
		Workspaces:  []OrgSettings{},
		Counts:      []Count{},
		Limits: []string{
			"A digest is not a safe way to publish a value that could be guessed from a short list. Only key material, " +
				"the passwords inside connection strings, and values whose setting name says they are secret are digested here; " +
				"everything else is printed as it is.",
			"This is the configuration of the process that ran the command. A gateway replica started with a different " +
				"environment is a different configuration, and nothing here would show it.",
			"Settings held per workspace are listed as rows, without interpretation: this report does not know which keys a " +
				"future release will read.",
		},
	}
	if err := d.DB.Bypass(ctx, "compliance:config-snapshot describes the instance and every workspace's settings", func(tx pgx.Tx) error {
		var err error
		if s.Instance, err = readInstance(ctx, tx, opts.Cfg); err != nil {
			return fmt.Errorf("read instance: %w", err)
		}
		if s.Site, err = readSiteSettings(ctx, tx); err != nil {
			return fmt.Errorf("read site settings: %w", err)
		}
		if s.Workspaces, err = readOrgSettings(ctx, tx); err != nil {
			return fmt.Errorf("read workspace settings: %w", err)
		}
		if s.Counts, err = readCounts(ctx, tx); err != nil {
			return fmt.Errorf("count the instance: %w", err)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return s, nil
}

// effectiveSettings reports the values the process resolved, not the
// variables it read them from. Two instances configured differently but
// resolving the same are the same instance as far as behaviour goes, and
// this is the section that shows it.
func effectiveSettings(cfg *config.Config) []Setting {
	if cfg == nil {
		return []Setting{}
	}
	set := func(name, value string) Setting { return Setting{Name: name, Value: value, Source: "effective"} }
	public := ""
	if cfg.PublicURL != nil {
		public = cfg.PublicURL.String()
	}
	out := []Setting{
		set("version", cfg.Version),
		set("listen", cfg.Listen),
		set("adminListen", orNone(cfg.AdminListen)),
		set("publicURL", public),
		{Name: "databaseURL", Value: RedactURL(cfg.DatabaseURL), Source: "effective", Redacted: true,
			Note: "the password is a digest; the host, database and parameters are as given, because whether the connection is encrypted is part of the configuration"},
		{Name: "maintDatabaseURL", Value: RedactURL(cfg.MaintDatabaseURL), Source: "effective", Redacted: true},
		{Name: "redisURL", Value: orNone(RedactURL(cfg.RedisURL)), Source: "effective", Redacted: cfg.RedisURL != "",
			Note: redisNote(cfg.RedisURL)},
		set("logLevel", cfg.LogLevel),
		set("logFormat", cfg.LogFormat),
		{Name: "dev", Value: strconv.FormatBool(cfg.Dev), Source: "effective", Note: devNote(cfg.Dev)},
		{Name: "openRegistration", Value: strconv.FormatBool(cfg.OpenRegistration), Source: "effective",
			Note: registrationNote(cfg.OpenRegistration)},
		set("dcrMode", cfg.DCRMode),
		set("mcpResponseMode", responseMode(cfg.MCPJSONResponse)),
		set("sqliteRoot", orNone(cfg.SQLiteRoot)),
		set("migrateOnStart", strconv.FormatBool(cfg.MigrateOnStart)),
		set("shutdownTimeout", cfg.ShutdownTimeout.String()),
		set("authFreshWindow", cfg.AuthFreshWindow.String()),
		{Name: "rateLimit.enabled", Value: strconv.FormatBool(cfg.RateLimit.Enabled), Source: "effective",
			Note: limiterNote(cfg.RateLimit.Enabled)},
		set("rateLimit.signIn", budget(cfg.RateLimit.Budgets.SignIn.Burst, cfg.RateLimit.Budgets.SignIn.Window)),
		set("rateLimit.register", budget(cfg.RateLimit.Budgets.Register.Burst, cfg.RateLimit.Budgets.Register.Window)),
		set("rateLimit.invite", budget(cfg.RateLimit.Budgets.Invite.Burst, cfg.RateLimit.Budgets.Invite.Window)),
		set("rateLimit.dcr", budget(cfg.RateLimit.Budgets.DCR.Burst, cfg.RateLimit.Budgets.DCR.Window)),
		set("rateLimit.toolCall", budget(cfg.RateLimit.Budgets.ToolCall.Burst, cfg.RateLimit.Budgets.ToolCall.Window)),
		set("rateLimit.analytics", budget(cfg.RateLimit.Budgets.Analytics.Burst, cfg.RateLimit.Budgets.Analytics.Window)),
		set("rateLimit.api", budget(cfg.RateLimit.Budgets.API.Burst, cfg.RateLimit.Budgets.API.Window)),
		set("rateLimit.maxKeys", strconv.Itoa(cfg.RateLimit.MaxKeys)),
		set("rateLimit.expectedReplicas", strconv.Itoa(cfg.RateLimit.ExpectedReplicas)),
		set("metrics.perTool", strconv.FormatBool(cfg.Metrics.PerTool)),
		set("metrics.perToolCap", strconv.Itoa(cfg.Metrics.PerToolCap)),
	}
	return out
}

func orNone(s string) string {
	if s == "" {
		return "(not set)"
	}
	return s
}

func responseMode(jsonMode bool) string {
	if jsonMode {
		return "json"
	}
	return "sse"
}

func budget(burst int, window time.Duration) string {
	return fmt.Sprintf("%d per %s", burst, window)
}

func devNote(dev bool) string {
	if dev {
		return "development mode: the public URL may be plain http and the session cookie is not marked Secure"
	}
	return ""
}

func registrationNote(open bool) string {
	if open {
		return "anyone who can reach the sign-up page can create an account"
	}
	return ""
}

func limiterNote(on bool) string {
	if on {
		return ""
	}
	return "the rate limiter is off; sign-in, registration and tool calls have no budget"
}

func redisNote(url string) string {
	switch {
	case url == "":
		return "no Redis: rate-limit budgets are divided per replica and the limiter reports that it is degraded"
	case strings.HasPrefix(url, "rediss://"):
		return ""
	default:
		return "the Redis connection is not TLS; use rediss:// if it crosses a network the operator does not own"
	}
}

// environment reports what an operator set. Every value is redacted on
// the strength of its name, because this section is the one most likely
// to be pasted into a ticket.
func environment(environ []string) []Setting {
	if environ == nil {
		environ = os.Environ()
	}
	out := []Setting{}
	for _, kv := range environ {
		name, value, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		if !strings.HasPrefix(name, "SUPERMCP_") && !known[name] {
			continue
		}
		s := Setting{Name: name, Value: value, Source: "set"}
		switch {
		case looksSecret(name):
			s.Value, s.Redacted = Digest(value), true
		case strings.HasSuffix(name, "_URL") && strings.Contains(value, "@"):
			s.Value, s.Redacted = RedactURL(value), true
		}
		if !known[name] {
			s.Note = "this binary does not read this variable; it is set and has no effect"
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func readInstance(ctx context.Context, tx pgx.Tx, cfg *config.Config) (Instance, error) {
	var inst Instance
	if cfg != nil {
		inst.BinaryVersion = cfg.Version
	}
	if err := tx.QueryRow(ctx, `SELECT id, created_at FROM instance ORDER BY created_at LIMIT 1`).
		Scan(&inst.ID, &inst.CreatedAt); err != nil {
		return inst, err
	}
	// The schema version is what decides whether the binary and the
	// database agree, so it belongs in any description of the instance.
	if err := tx.QueryRow(ctx, `SELECT COALESCE(max(version_id), 0) FROM goose_db_version WHERE is_applied`).
		Scan(&inst.SchemaVersion); err != nil {
		return inst, err
	}
	return inst, nil
}

func readSiteSettings(ctx context.Context, tx pgx.Tx) ([]Setting, error) {
	rows, err := tx.Query(ctx, `SELECT key, value::text FROM site_settings ORDER BY key`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Setting{}
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			return nil, err
		}
		out = append(out, storedSetting(key, value))
	}
	return out, rows.Err()
}

func readOrgSettings(ctx context.Context, tx pgx.Tx) ([]OrgSettings, error) {
	rows, err := tx.Query(ctx, `
SELECT o.id, o.slug, s.key, s.value::text
FROM organizations o LEFT JOIN org_settings s ON s.organization_id = o.id
ORDER BY o.slug, s.key`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []OrgSettings{}
	for rows.Next() {
		var id, slug string
		var key, value *string
		if err := rows.Scan(&id, &slug, &key, &value); err != nil {
			return nil, err
		}
		if len(out) == 0 || out[len(out)-1].OrgID != id {
			out = append(out, OrgSettings{OrgID: id, Slug: slug, Settings: []Setting{}})
		}
		if key == nil || value == nil {
			continue
		}
		cur := &out[len(out)-1]
		cur.Settings = append(cur.Settings, storedSetting(*key, *value))
	}
	return out, rows.Err()
}

func storedSetting(key, value string) Setting {
	s := Setting{Name: key, Value: value, Source: "database"}
	if looksSecret(key) {
		s.Value, s.Redacted = Digest(value), true
	}
	return s
}

// readCounts is one statement so the numbers all describe the same
// instant. Separate queries would be cheaper to read and would let a
// connector created between two of them appear in one count and not the
// other.
func readCounts(ctx context.Context, tx pgx.Tx) ([]Count, error) {
	var (
		orgs, users, members, accounts, keys, connectors, tools, servers int64
		idps, exporters, dlp, approvals, roles, events, invocations      int64
	)
	err := tx.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM organizations),
		(SELECT count(*) FROM users),
		(SELECT count(*) FROM organization_members WHERE deactivated_at IS NULL),
		(SELECT count(*) FROM service_accounts WHERE disabled_at IS NULL),
		(SELECT count(*) FROM api_keys WHERE revoked_at IS NULL),
		(SELECT count(*) FROM connectors),
		(SELECT count(*) FROM tools),
		(SELECT count(*) FROM mcp_servers),
		(SELECT count(*) FROM identity_providers WHERE enabled),
		(SELECT count(*) FROM audit_exporters WHERE enabled),
		(SELECT count(*) FROM dlp_policies WHERE enabled),
		(SELECT count(*) FROM approval_policies WHERE enabled),
		(SELECT count(*) FROM roles WHERE NOT is_system),
		(SELECT count(*) FROM audit_events),
		(SELECT count(*) FROM tool_invocations)`).
		Scan(&orgs, &users, &members, &accounts, &keys, &connectors, &tools, &servers,
			&idps, &exporters, &dlp, &approvals, &roles, &events, &invocations)
	if err != nil {
		return nil, err
	}
	return []Count{
		{"workspaces", orgs},
		{"user accounts", users},
		{"live memberships", members},
		{"service accounts in use", accounts},
		{"API keys not revoked", keys},
		{"connectors", connectors},
		{"tools", tools},
		{"MCP servers", servers},
		{"identity providers enabled", idps},
		{"audit exporters enabled", exporters},
		{"data-loss policies enabled", dlp},
		{"approval policies enabled", approvals},
		{"custom roles", roles},
		{"audit events", events},
		{"tool calls recorded", invocations},
	}, nil
}
