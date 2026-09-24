// Master key selection. Everything that decides which key protects an
// installation's data keys is resolved here, once, at start-up, so a
// misconfiguration is a boot failure rather than a surprise the first
// time a tenant saves a credential.
//
// The rule the rest of this file exists to enforce: a provider that
// cannot be built is an error, never a downgrade. Falling back to the
// local key because KMS was unreachable would leave the master key in a
// pod's environment on a deployment that was configured not to have one
// there, and — worse — would seal new data keys under it, so the mistake
// would still be silently protecting secrets months later.

package secrets

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// Providers understood by SUPERMCP_KEK_PROVIDER.
const (
	ProviderLocal  = "local"
	ProviderAWSKMS = "awskms"
)

// Settings. Named constants because every error message quotes the
// setting an operator has to change.
const (
	envKEKProvider   = "SUPERMCP_KEK_PROVIDER"
	envKEKPrevious   = "SUPERMCP_KEK_PREVIOUS"
	envKMSKeyID      = "SUPERMCP_KMS_KEY_ID"
	envKMSRegion     = "SUPERMCP_KMS_REGION"
	envKMSDeployment = "SUPERMCP_KMS_DEPLOYMENT"
	envKMSTimeout    = "SUPERMCP_KMS_TIMEOUT"
	envLocalKEK      = "ENCRYPTION_KEK"
)

// previousSeparator splits a decrypt-only entry's reference from its
// material. It is outside the base64 alphabet, so an entry that carries
// no reference is never mistaken for one that does.
const previousSeparator = "|"

// KEKSet is the master keys a process holds: exactly one that seals, and
// any number that may only open. During a rotation an operator names the
// outgoing key here so both halves of a rolling deployment can read
// everything in the database.
type KEKSet struct {
	Active   KEK
	Previous []KEK
}

// Find returns the key that may open material recorded against ref.
func (s *KEKSet) Find(ref string) (KEK, bool) {
	if s == nil || s.Active == nil {
		return nil, false
	}
	if ref == s.Active.Ref() {
		return s.Active, true
	}
	for _, k := range s.Previous {
		if k.Ref() == ref {
			return k, true
		}
	}
	return nil, false
}

// KEKFromEnv builds the master keys from configuration. Settings are read
// through get, as LocalFromEnv reads them, so a caller can resolve them
// from somewhere other than the process environment and so tests need no
// global state.
//
// ctx bounds the provider's own start-up work: building the AWS client
// resolves credentials, which can mean a call to the instance metadata
// service, and a pod hanging on that is worse than a pod that fails.
func KEKFromEnv(ctx context.Context, get func(string) string) (*KEKSet, error) {
	return kekFromEnv(ctx, get, AWSKMSConfig{})
}

// kekFromEnv carries a base AWS configuration the caller may pre-fill.
// It exists so tests can supply a KMSClient and exercise the selection
// without reaching AWS; production goes through KEKFromEnv.
func kekFromEnv(ctx context.Context, get func(string) string, base AWSKMSConfig) (*KEKSet, error) {
	provider := strings.ToLower(strings.TrimSpace(get(envKEKProvider)))
	if provider == "" {
		provider = ProviderLocal
	}
	var (
		active KEK
		err    error
	)
	switch provider {
	case ProviderLocal:
		active, err = LocalFromEnv(get)
	case ProviderAWSKMS:
		active, err = awsKMSFromEnv(ctx, get, base)
	default:
		return nil, fmt.Errorf("%s is %q, want %s or %s", envKEKProvider, provider, ProviderLocal, ProviderAWSKMS)
	}
	if err != nil {
		return nil, fmt.Errorf("%s=%s: %w", envKEKProvider, provider, err)
	}

	previous, err := previousKEKs(get)
	if err != nil {
		return nil, err
	}
	for _, k := range previous {
		// Two keys under one reference cannot be told apart by anything
		// that reads data_keys.kek_ref, so a rotation between them would
		// skip every row as already done. Refusing here points the
		// operator at the fix: give the incoming local key its own
		// reference by loading it from ENCRYPTION_KEK_FILE.
		if k.Ref() == active.Ref() {
			return nil, fmt.Errorf("%s names %s, which is also the active key's reference; a local rotation needs two references, so load the new key from ENCRYPTION_KEK_FILE", envKEKPrevious, k.Ref())
		}
	}
	return &KEKSet{Active: active, Previous: previous}, nil
}

// awsKMSFromEnv reads the KMS settings. Each check names the setting that
// is wrong, because the alternative — a generic "kms configuration is
// incomplete" in a crash loop — tells an operator nothing at three in the
// morning.
func awsKMSFromEnv(ctx context.Context, get func(string) string, cfg AWSKMSConfig) (*AWSKMS, error) {
	cfg.KeyID = strings.TrimSpace(get(envKMSKeyID))
	cfg.Deployment = strings.TrimSpace(get(envKMSDeployment))
	if cfg.KeyID == "" {
		return nil, fmt.Errorf("%w: set %s to a key id, key arn, or an alias such as alias/supermcp", ErrKMSConfig, envKMSKeyID)
	}
	cfg.Region = strings.TrimSpace(get(envKMSRegion))
	if cfg.Region == "" {
		// A pod running under a workload identity already has AWS_REGION
		// set by the platform, and a region that disagrees with the one
		// the SDK would use is a confusing failure; prefer the explicit
		// setting and accept the platform's as the default.
		cfg.Region = strings.TrimSpace(get("AWS_REGION"))
	}
	if cfg.Region == "" {
		cfg.Region = strings.TrimSpace(get("AWS_DEFAULT_REGION"))
	}
	if cfg.Region == "" {
		return nil, fmt.Errorf("%w: set %s to the region holding %s", ErrKMSConfig, envKMSRegion, cfg.KeyID)
	}
	if v := strings.TrimSpace(get(envKMSTimeout)); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return nil, fmt.Errorf("%s is %q, want a duration such as 10s: %w", envKMSTimeout, v, err)
		}
		if d <= 0 {
			return nil, fmt.Errorf("%s is %q, want a positive duration", envKMSTimeout, v)
		}
		cfg.Timeout = d
	}
	return NewAWSKMSFromConfig(ctx, cfg)
}

// previousKEKs parses SUPERMCP_KEK_PREVIOUS: a comma-separated list of
// local keys that may decrypt and never seal. An entry is either the
// base64 material on its own, which takes the reference a key configured
// through ENCRYPTION_KEK carries, or "<reference>|<base64>" for a key
// that was loaded from a file and so recorded a different one. The
// reference is the deciding part: it has to match data_keys.kek_ref
// exactly or the key will never be chosen, so it is accepted both with
// and without the "local:" prefix an operator reads out of the table.
func previousKEKs(get func(string) string) ([]KEK, error) {
	raw := strings.TrimSpace(get(envKEKPrevious))
	if raw == "" {
		return nil, nil
	}
	parts := strings.Split(raw, ",")
	out := make([]KEK, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for i, part := range parts {
		entry := strings.TrimSpace(part)
		if entry == "" {
			continue
		}
		ref, material := "env:"+envLocalKEK, entry
		if before, after, ok := strings.Cut(entry, previousSeparator); ok {
			ref, material = strings.TrimSpace(before), strings.TrimSpace(after)
		}
		ref = strings.TrimPrefix(ref, "local:")
		if ref == "" || material == "" {
			return nil, fmt.Errorf("%s entry %d is incomplete, want <base64> or <reference>|<base64>", envKEKPrevious, i+1)
		}
		k, err := NewLocal(material, ref)
		if err != nil {
			return nil, fmt.Errorf("%s entry %d (%s): %w", envKEKPrevious, i+1, ref, err)
		}
		if _, dup := seen[k.Ref()]; dup {
			return nil, fmt.Errorf("%s names %s twice", envKEKPrevious, k.Ref())
		}
		seen[k.Ref()] = struct{}{}
		out = append(out, k)
	}
	return out, nil
}
