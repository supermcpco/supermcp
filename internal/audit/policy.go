package audit

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/supermcpco/supermcp/internal/tenant"
)

// What a tool call stores alongside the fact that it happened is the
// organisation's decision, not ours. An investigation wants the arguments;
// a regulator may forbid keeping them. The default is the middle: enough
// to reconstruct who called what, and nothing the caller typed.

// DefaultPayloadMode applies when an organisation has not chosen.
const DefaultPayloadMode = PayloadMetadata

// payloadSetting is the org_settings key holding the choice.
const payloadSetting = "audit.payload"

// policyTTL keeps the read off the tool-call path without making a change
// take effect tomorrow.
const policyTTL = 30 * time.Second

type policyEntry struct {
	mode PayloadMode
	at   time.Time
}

// Policies reads each organisation's payload policy, with a short cache.
type Policies struct {
	DB *tenant.DB

	mu    sync.Mutex
	cache map[string]policyEntry
	now   func() time.Time
}

// NewPolicies builds the reader.
func NewPolicies(db *tenant.DB) *Policies {
	return &Policies{DB: db, cache: map[string]policyEntry{}, now: time.Now}
}

// Mode returns the organisation's payload policy.
func (p *Policies) Mode(ctx context.Context, orgID string) PayloadMode {
	if p == nil || orgID == "" {
		return DefaultPayloadMode
	}
	p.mu.Lock()
	if e, ok := p.cache[orgID]; ok && p.now().Sub(e.at) < policyTTL {
		p.mu.Unlock()
		return e.mode
	}
	p.mu.Unlock()

	mode := DefaultPayloadMode
	var raw []byte
	err := p.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT value FROM org_settings WHERE organization_id = $1 AND key = $2`,
			orgID, payloadSetting).Scan(&raw)
	})
	if err == nil {
		var v string
		if err := json.Unmarshal(raw, &v); err == nil {
			switch PayloadMode(v) {
			case PayloadNone, PayloadMetadata, PayloadMasked, PayloadFull:
				mode = PayloadMode(v)
			}
		}
	} else if !errors.Is(err, pgx.ErrNoRows) {
		// A policy we cannot read is not a reason to store more than the
		// default would.
		mode = DefaultPayloadMode
	}

	p.mu.Lock()
	p.cache[orgID] = policyEntry{mode: mode, at: p.now()}
	p.mu.Unlock()
	return mode
}

// SetMode stores an organisation's choice.
func (p *Policies) SetMode(ctx context.Context, orgID string, mode PayloadMode) error {
	switch mode {
	case PayloadNone, PayloadMetadata, PayloadMasked, PayloadFull:
	default:
		return errors.New("the payload policy must be none, metadata, masked or full")
	}
	value, err := json.Marshal(string(mode))
	if err != nil {
		return err
	}
	err = p.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO org_settings (organization_id, key, value) VALUES ($1,$2,$3)
			ON CONFLICT (organization_id, key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`,
			orgID, payloadSetting, value)
		return err
	})
	if err != nil {
		return err
	}
	p.mu.Lock()
	delete(p.cache, orgID)
	p.mu.Unlock()
	return nil
}

// Apply reduces a tool call's input and output to what the policy allows.
// It returns what should be stored, which may be nothing.
func Apply(mode PayloadMode, input, output any) (any, any) {
	switch mode {
	case PayloadNone:
		return nil, nil
	case PayloadFull:
		return input, output
	case PayloadMasked:
		return mask(input), mask(output)
	default: // metadata
		return shape(input), shape(output)
	}
}

// shape keeps the structure and drops the values: which arguments were
// given, and what kind each was, without what was in them.
func shape(v any) any {
	switch x := v.(type) {
	case nil:
		return nil
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			out[k] = kindOf(val)
		}
		return out
	case []any:
		return map[string]any{"_type": "array", "_len": len(x)}
	case string:
		return map[string]any{"_type": "string", "_len": len(x)}
	}
	return kindOf(v)
}

func kindOf(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case bool:
		return "boolean"
	case float64, int, int64:
		return "number"
	case string:
		return "string"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	}
	return "value"
}

// Patterns worth masking wherever they appear. This is not data-loss
// prevention, which arrives in v1.1 with its own detectors and policies;
// it is the floor, so "masked" never stores a card number verbatim.
var maskPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\b(?:\d[ -]?){13,19}\b`),                                    // payment card
	regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`),          // email address
	regexp.MustCompile(`\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b`),                          // IBAN
	regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),                                     // US social security number
	regexp.MustCompile(`(?i)\b(?:sk|pk|smk|ghp|xox[baprs])[-_][A-Za-z0-9\-_]{16,}`), // API keys and tokens
}

// mask walks a value and redacts what looks sensitive inside its strings.
func mask(v any) any {
	switch x := v.(type) {
	case nil:
		return nil
	case string:
		return maskString(x)
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			// A key that names a secret is redacted whatever it holds.
			if looksSecret(k) {
				out[k] = "<redacted>"
				continue
			}
			out[k] = mask(val)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = mask(e)
		}
		return out
	}
	return v
}

// MaskText redacts what the "masked" payload policy redacts in a string
// (card numbers, email addresses, IBANs, US social security numbers and
// API-key shaped tokens), whatever the organisation's policy is. It is for
// text that is kept regardless of the policy, such as a tool call's error,
// which can quote what the call was given.
func MaskText(s string) string { return maskString(s) }

func maskString(s string) string {
	for _, re := range maskPatterns {
		s = re.ReplaceAllString(s, "<redacted>")
	}
	return s
}

var secretNames = []string{"password", "secret", "token", "apikey", "api_key", "authorization", "credential", "passwd", "pwd"}

func looksSecret(key string) bool {
	k := strings.ToLower(key)
	for _, name := range secretNames {
		if strings.Contains(k, name) {
			return true
		}
	}
	return false
}
