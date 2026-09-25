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
	"errors"
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
	// The same key in another region, as the Sealer would pick it.
	for _, k := range append([]KEK{s.Active}, s.Previous...) {
		if o, ok := openerFor(k, ref); ok {
			return o, true
		}
	}
	return nil, false
}

// Which configured key opens a data key, as DataKeyCheck.HeldBy reports
// it.
const (
	HeldByActive   = "active"
	HeldByPrevious = "previous"
	// HeldByReplica is the active or a previous key opening what its
	// multi-Region replica in another region wrapped.
	HeldByReplica = "replica"
)

// DataKeyCheck is one data key's standing against a KEKSet.
type DataKeyCheck struct {
	Key *DataKey
	// Active reports that the key is recorded under the active key's
	// reference, so a master key rotation has nothing left to do for it.
	// Once every key is, the previous keys can be dropped.
	Active bool
	// HeldBy is HeldByActive, HeldByPrevious, HeldByReplica, or empty when
	// no key in the set has the reference.
	HeldBy string
	// Err is why the key did not open, nil when it did.
	Err error
}

// Check opens every data key with the key its own row names, never with
// every key in turn, and throws the material away again. It stops only
// when ctx does; a key that does not open is reported, not returned as
// an error, because during a rotation the useful answer is how many are
// stranded and under which reference, not which one failed first.
func (s *KEKSet) Check(ctx context.Context, keys []*DataKey) ([]DataKeyCheck, error) {
	out := make([]DataKeyCheck, 0, len(keys))
	for _, dk := range keys {
		if err := ctx.Err(); err != nil {
			return out, fmt.Errorf("check stopped after %d of %d data keys: %w", len(out), len(keys), err)
		}
		c := DataKeyCheck{Key: dk, Active: s != nil && s.Active != nil && dk.KEKRef == s.Active.Ref()}
		kek, ok := s.Find(dk.KEKRef)
		switch {
		case !ok:
			c.Err = errors.New("this process holds no key with that reference")
			out = append(out, c)
			continue
		case c.Active:
			c.HeldBy = HeldByActive
		case s.isPrevious(dk.KEKRef):
			c.HeldBy = HeldByPrevious
		default:
			c.HeldBy = HeldByReplica
		}
		c.Err = openAndDiscard(ctx, kek, dk.Wrapped)
		out = append(out, c)
	}
	return out, nil
}

func (s *KEKSet) isPrevious(ref string) bool {
	for _, k := range s.Previous {
		if k.Ref() == ref {
			return true
		}
	}
	return false
}

// openAndDiscard unwraps a data key and zeroes it at once: the caller
// only needs to know that it opens, and holding every tenant's data key
// in one heap for the length of a run is what it must not do.
func openAndDiscard(ctx context.Context, kek KEK, wrapped []byte) error {
	dek, err := kek.Unwrap(ctx, wrapped)
	if err != nil {
		return err
	}
	defer zeroKey(dek)
	if len(dek) != dekLen {
		return fmt.Errorf("unwrapped to %d bytes, want %d", len(dek), dekLen)
	}
	return nil
}

// KEKFromEnv builds the master keys from configuration. Settings are read
// through get, as LocalFromEnv reads them, so a caller can resolve them
// from somewhere other than the process environment and so tests need no
// global state.
//
// ctx bounds the providers' own start-up work: building an AWS client
// resolves credentials, which can mean a call to the instance metadata
// service, and a pod hanging on that is worse than a pod that fails.
func KEKFromEnv(ctx context.Context, get func(string) string) (*KEKSet, error) {
	return kekFromEnv(ctx, get, nil)
}

// kmsClients hands out the KMS client for a region. Nil means the AWS
// default chain, which is what production uses; tests supply a fake so
// the selection can be exercised without reaching AWS. The active key
// and every previous one go through the same factory, so a previous key
// is opened exactly the way it was when it was the active one.
type kmsClients func(region string) KMSClient

func (c kmsClients) forRegion(region string) KMSClient {
	if c == nil {
		return nil
	}
	return c(region)
}

func kekFromEnv(ctx context.Context, get func(string) string, clients kmsClients) (*KEKSet, error) {
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
		active, err = awsKMSFromEnv(ctx, get, clients)
	default:
		return nil, fmt.Errorf("%s is %q, want %s or %s", envKEKProvider, provider, ProviderLocal, ProviderAWSKMS)
	}
	if err != nil {
		return nil, fmt.Errorf("%s=%s: %w", envKEKProvider, provider, err)
	}

	previous, err := previousKEKs(ctx, get, clients)
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
			if ProviderOf(k.Ref()) == ProviderAWSKMS {
				return nil, fmt.Errorf("%s names %s, which is the active key; a key cannot be its own previous key, so name the key being moved away from", envKEKPrevious, k.Ref())
			}
			return nil, fmt.Errorf("%s names %s, which is also the active key's reference; a local rotation needs two references, so load the new key from ENCRYPTION_KEK_FILE", envKEKPrevious, k.Ref())
		}
		if why, same := sameKMSKey(active.Ref(), k.Ref()); same {
			return nil, fmt.Errorf("%s names %s, %s", envKEKPrevious, k.Ref(), why)
		}
	}
	return &KEKSet{Active: active, Previous: previous}, nil
}

// kmsSettings is what every KMS key in a process shares unless an entry
// says otherwise.
type kmsSettings struct {
	region     string
	deployment string
	timeout    time.Duration
}

// readKMSSettings reads the settings that are not the key id. Each check
// names the setting that is wrong, because the alternative — a generic
// "kms configuration is incomplete" in a crash loop — tells an operator
// nothing at three in the morning.
func readKMSSettings(get func(string) string) (kmsSettings, error) {
	s := kmsSettings{
		deployment: strings.TrimSpace(get(envKMSDeployment)),
		region:     strings.TrimSpace(get(envKMSRegion)),
	}
	if s.region == "" {
		// A pod running under a workload identity already has AWS_REGION
		// set by the platform, and a region that disagrees with the one
		// the SDK would use is a confusing failure; prefer the explicit
		// setting and accept the platform's as the default.
		s.region = strings.TrimSpace(get("AWS_REGION"))
	}
	if s.region == "" {
		s.region = strings.TrimSpace(get("AWS_DEFAULT_REGION"))
	}
	if v := strings.TrimSpace(get(envKMSTimeout)); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return s, fmt.Errorf("%s is %q, want a duration such as 10s: %w", envKMSTimeout, v, err)
		}
		if d <= 0 {
			return s, fmt.Errorf("%s is %q, want a positive duration", envKMSTimeout, v)
		}
		s.timeout = d
	}
	return s, nil
}

// awsKMSFromEnv builds the active KMS key.
func awsKMSFromEnv(ctx context.Context, get func(string) string, clients kmsClients) (*AWSKMS, error) {
	keyID := strings.TrimSpace(get(envKMSKeyID))
	if keyID == "" {
		return nil, fmt.Errorf("%w: set %s to a key id, key arn, or an alias such as alias/supermcp", ErrKMSConfig, envKMSKeyID)
	}
	s, err := readKMSSettings(get)
	if err != nil {
		return nil, err
	}
	if s.region == "" {
		return nil, fmt.Errorf("%w: set %s to the region holding %s", ErrKMSConfig, envKMSRegion, keyID)
	}
	return NewAWSKMSFromConfig(ctx, AWSKMSConfig{
		KeyID: keyID, Region: s.region, Deployment: s.deployment,
		Timeout: s.timeout, Client: clients.forRegion(s.region),
	})
}

// previousKEKs parses SUPERMCP_KEK_PREVIOUS: a comma-separated list of
// master keys that may decrypt and never seal. An entry is one of
//
//   - the base64 material of a local key on its own, which takes the
//     reference a key configured through ENCRYPTION_KEK carries;
//   - "<reference>|<base64>" for a local key that was loaded from a file
//     and so recorded a different one;
//   - "awskms:<key>" for a KMS key; see kmsEntry for the spelling.
//
// The reference is the deciding part: it has to match data_keys.kek_ref
// exactly or the key will never be chosen, so a local one is accepted
// both with and without the "local:" prefix an operator reads out of the
// table, and a KMS one may be pasted from the table as it stands.
func previousKEKs(ctx context.Context, get func(string) string, clients kmsClients) ([]KEK, error) {
	raw := strings.TrimSpace(get(envKEKPrevious))
	if raw == "" {
		return nil, nil
	}
	parts := strings.Split(raw, ",")
	out := make([]KEK, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	var kms *kmsSettings // read once, and only if an entry needs it
	for i, part := range parts {
		entry := strings.TrimSpace(part)
		if entry == "" {
			continue
		}
		var (
			k   KEK
			err error
		)
		if strings.HasPrefix(entry, "awskms:") {
			if kms == nil {
				s, err := readKMSSettings(get)
				if err != nil {
					return nil, err
				}
				kms = &s
			}
			k, err = previousKMS(ctx, entry, *kms, clients)
			if err != nil {
				return nil, fmt.Errorf("%s entry %d (%s): %w", envKEKPrevious, i+1, entry, err)
			}
		} else {
			ref, material := "env:"+envLocalKEK, entry
			if before, after, ok := strings.Cut(entry, previousSeparator); ok {
				ref, material = strings.TrimSpace(before), strings.TrimSpace(after)
			}
			ref = strings.TrimPrefix(ref, "local:")
			if ref == "" || material == "" {
				return nil, fmt.Errorf("%s entry %d is incomplete, want <base64>, <reference>|<base64> or awskms:<key>", envKEKPrevious, i+1)
			}
			k, err = NewLocal(material, ref)
			if err != nil {
				return nil, fmt.Errorf("%s entry %d (%s): %w", envKEKPrevious, i+1, ref, err)
			}
		}
		if _, dup := seen[k.Ref()]; dup {
			return nil, fmt.Errorf("%s names %s twice", envKEKPrevious, k.Ref())
		}
		seen[k.Ref()] = struct{}{}
		out = append(out, k)
	}
	return out, nil
}

// previousKMS builds a decrypt-only KMS key from one entry, with the same
// client factory, timeout and, unless the entry names its own, the same
// deployment as the active key.
func previousKMS(ctx context.Context, entry string, s kmsSettings, clients kmsClients) (*AWSKMS, error) {
	e, err := parseKMSEntry(entry)
	if err != nil {
		return nil, err
	}
	region := e.region
	if region == "" {
		region = s.region
	}
	if region == "" {
		return nil, fmt.Errorf("%w: add @<region> to the entry, or set %s", ErrKMSConfig, envKMSRegion)
	}
	deployment := s.deployment
	if e.deploymentSet {
		deployment = e.deployment
	}
	return NewAWSKMSFromConfig(ctx, AWSKMSConfig{
		KeyID: e.keyID, Region: region, Deployment: deployment,
		Timeout: s.timeout, Client: clients.forRegion(region),
	})
}

// kmsEntry is one "awskms:" entry of SUPERMCP_KEK_PREVIOUS taken apart.
type kmsEntry struct {
	keyID  string
	region string // empty: the region the active settings name
	// deployment replaces SUPERMCP_KMS_DEPLOYMENT for this key when
	// deploymentSet. An empty one means "was never configured", which
	// makes the key's own reference the encryption context, as it was.
	deployment    string
	deploymentSet bool
}

// parseKMSEntry reads
//
//	awskms:<key>[@<region>][#<deployment>]
//
// where <key> is a key id, an alias ("alias/supermcp") or an ARN, the
// same spellings SUPERMCP_KMS_KEY_ID takes. The stored reference is
// accepted as well: "awskms:<region>/<key>" is what data_keys.kek_ref
// holds, and pasting that is the least error-prone way to name the key
// that wrapped a row. An ARN carries its region, so "@" beside one is
// refused rather than silently overruled.
//
// Neither separator can occur in a key id, an alias name, an ARN or a
// region, so the three parts never bleed into each other.
func parseKMSEntry(entry string) (kmsEntry, error) {
	rest := strings.TrimSpace(strings.TrimPrefix(entry, "awskms:"))
	var e kmsEntry
	if strings.Contains(rest, previousSeparator) {
		return e, errors.New("a KMS entry carries no key material; write awskms:<key>[@<region>]")
	}
	if before, after, ok := strings.Cut(rest, "#"); ok {
		rest, e.deployment, e.deploymentSet = before, strings.TrimSpace(after), true
	}
	if before, after, ok := strings.Cut(rest, "@"); ok {
		rest, e.region = before, strings.TrimSpace(after)
		if e.region == "" {
			return e, errors.New("the region after @ is empty")
		}
	}
	rest = strings.TrimSpace(rest)
	switch {
	case rest == "":
		return e, errors.New("the key is empty; write awskms:<key id, alias or ARN>")
	case strings.HasPrefix(rest, "arn:"):
		ref, ok := parseKMSRef("awskms:" + rest)
		if !ok {
			return e, fmt.Errorf("%q is not a KMS key or alias ARN", rest)
		}
		if e.region != "" && e.region != ref.region {
			return e, fmt.Errorf("the ARN is in %s and the entry says @%s; an ARN carries its region, so drop the @", ref.region, e.region)
		}
		e.region = ref.region
	case !strings.HasPrefix(rest, "alias/") && strings.Contains(rest, "/"):
		// "<region>/<key>", as data_keys.kek_ref spells it. A key id has
		// no slash, and an alias starts with "alias/", so nothing else
		// reaches here.
		region, key, _ := strings.Cut(rest, "/")
		if e.region != "" {
			return e, fmt.Errorf("the entry names region %s twice, as %s/ and @%s", region, region, e.region)
		}
		if key == "" {
			return e, errors.New("the key after the region is empty")
		}
		rest, e.region = key, region
	}
	e.keyID = rest
	return e, nil
}

// sameKMSKey reports whether the previous key's reference b names the
// active key a, and says how, for the error that refuses it. It is only as good as the
// references allow: an alias and the key id it points at look unrelated
// until KMS is asked, and asking would need kms:DescribeKey, which a key
// policy granting only what wrapping needs does not give. That case is
// harmless anyway; rotate-kek just moves the rows from one spelling of
// the key to the other.
func sameKMSKey(a, b string) (string, bool) {
	ra, okA := parseKMSRef(a)
	rb, okB := parseKMSRef(b)
	if !okA || !okB || ra.resource != rb.resource {
		return "", false
	}
	if ra.partition != "" && rb.partition != "" && ra.partition != rb.partition {
		return "", false
	}
	if ra.account != "" && rb.account != "" && ra.account != rb.account {
		return "", false
	}
	if ra.region == rb.region {
		// A key id and its ARN in one region, or two spellings of one
		// alias ARN. An alias is only the same key in the same region.
		return fmt.Sprintf("which is another spelling of the active key %s; a move needs a different key", a), true
	}
	if strings.HasPrefix(ra.resource, "mrk-") {
		// A replica holds the same key material, and the active key
		// already opens what its replicas wrapped without being told.
		return fmt.Sprintf("which is a multi-Region replica of the active key %s; the active key already opens what a replica wrapped, so the entry is not needed", a), true
	}
	return "", false
}
