package secrets

import (
	"context"
	"strings"
)

// KEK operation names, as reported to a KEKObserver.
const (
	OpWrap   = "wrap"
	OpUnwrap = "unwrap"
)

// KEKObserver is told the outcome of each master key operation: the
// provider (ProviderLocal, ProviderAWSKMS), OpWrap or OpUnwrap, and the
// error, nil on success.
type KEKObserver func(provider, op string, err error)

// observedKEK reports every Wrap and Unwrap to an observer and otherwise
// changes nothing.
type observedKEK struct {
	KEK
	provider string
	observe  KEKObserver
}

// Observed returns k with every Wrap and Unwrap reported to observe. It
// sits in front of the master key rather than the Sealer because the
// Sealer caches unwrapped data keys: what reaches the KEK is exactly the
// traffic that reaches KMS, so an error here is KMS failing a call that
// something needed, not noise from a warm cache.
//
// A call whose caller had already given up is not reported. A request
// cancelled mid-flight fails its KMS call too, and counting that would
// make a client hanging up look like the key service going away.
func Observed(k KEK, observe KEKObserver) KEK {
	if k == nil || observe == nil {
		return k
	}
	return &observedKEK{KEK: k, provider: ProviderOf(k.Ref()), observe: observe}
}

// forRef keeps an observed key's cross-region opener observed too.
func (o *observedKEK) forRef(ref string) (KEK, bool) {
	k, ok := openerFor(o.KEK, ref)
	if !ok {
		return nil, false
	}
	return &observedKEK{KEK: k, provider: o.provider, observe: o.observe}, true
}

// Wrap implements KEK.
func (o *observedKEK) Wrap(ctx context.Context, dek []byte) ([]byte, error) {
	out, err := o.KEK.Wrap(ctx, dek)
	o.report(ctx, OpWrap, err)
	return out, err
}

// Unwrap implements KEK.
func (o *observedKEK) Unwrap(ctx context.Context, wrapped []byte) ([]byte, error) {
	out, err := o.KEK.Unwrap(ctx, wrapped)
	o.report(ctx, OpUnwrap, err)
	return out, err
}

func (o *observedKEK) report(ctx context.Context, op string, err error) {
	if err != nil && ctx.Err() != nil {
		return
	}
	o.observe(o.provider, op, err)
}

// ProviderOf names the provider behind a KEK reference, as recorded in
// data_keys.kek_ref: ProviderLocal, ProviderAWSKMS, or "" for a reference
// neither provider would have written.
func ProviderOf(ref string) string {
	switch {
	case strings.HasPrefix(ref, "awskms:"):
		return ProviderAWSKMS
	case strings.HasPrefix(ref, "local:"):
		return ProviderLocal
	default:
		return ""
	}
}
