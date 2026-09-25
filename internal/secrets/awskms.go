package secrets

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// kmsPlaintextLimit is the largest plaintext KMS Encrypt accepts. A data
// key is 32 bytes, so hitting this means the caller passed something that
// is not a data key.
const kmsPlaintextLimit = 4096

// defaultKMSTimeout bounds a single KMS round trip. Without it a stalled
// connection would hold a request goroutine for as long as the SDK's own
// retry budget allows, and wrapping happens on the path that creates an
// organisation's first credential.
const defaultKMSTimeout = 10 * time.Second

// ErrKMSConfig reports a KEK that cannot be built from the given settings.
var ErrKMSConfig = errors.New("aws kms configuration is incomplete")

// ErrKeyServiceUnavailable marks a key service call that failed because
// the service could not be reached or could not answer: the connection
// failed, the call timed out, the service was throttling, or it answered
// with a server-side fault. The same call can succeed later. It is
// wrapped alongside the provider's own error, so both stay reachable with
// errors.Is and errors.As.
//
// A refusal is not this: a ciphertext the service rejects, a key policy
// that denies the call, a disabled key. Those are configuration or data
// problems, and retrying changes nothing.
var ErrKeyServiceUnavailable = errors.New("key service unavailable")

// KMSClient is the part of the KMS API this package uses. It is declared
// here, at the consumer, so tests can supply a fake and so no AWS type
// appears in the KEK contract.
type KMSClient interface {
	Encrypt(ctx context.Context, in *kms.EncryptInput, optFns ...func(*kms.Options)) (*kms.EncryptOutput, error)
	Decrypt(ctx context.Context, in *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error)
}

// AWSKMSConfig builds an AWSKMS. Everything is supplied by the caller
// rather than read from the environment here, so that the process has one
// place where configuration is resolved and validated.
type AWSKMSConfig struct {
	// KeyID is a key id, key ARN, alias name ("alias/supermcp") or alias
	// ARN. An alias is the usual choice: it survives replacing the key
	// underneath, and it is what makes AWS's own yearly key rotation
	// invisible to this process.
	KeyID string
	// Region is required even when KeyID is an ARN, because it is also the
	// endpoint the client talks to and a silent mismatch between the two
	// is worth refusing outright.
	Region string
	// Deployment names this installation. It is the part of the encryption
	// context that stops a wrapped key lifted from one installation's
	// database from being unwrapped by another: staging and production
	// routinely share an AWS account and frequently share a KMS key, so
	// the key's own identity separates nothing. Left empty it falls back
	// to the key reference, which separates installations only as far as
	// they use different keys.
	Deployment string
	// Client overrides the constructed KMS client. Tests set it; so could
	// a caller that already holds a configured client.
	Client KMSClient
	// Timeout bounds a single KMS call. Zero means defaultKMSTimeout.
	Timeout time.Duration
}

// AWSKMS wraps data keys with a KMS customer master key. The data key
// itself never leaves this process in the clear and never reaches AWS in
// any form other than a single Encrypt call, so a compromised pod leaks
// the keys it has already unwrapped and nothing else; unlike Local, there
// is no master key in the pod's environment to read.
type AWSKMS struct {
	client     KMSClient
	keyID      string
	deployment string
	ref        string
	timeout    time.Duration
}

var _ KEK = (*AWSKMS)(nil)

// NewAWSKMS builds a KEK backed by the KMS key keyID in region.
// Credentials come from the AWS default chain, which is what lets a pod
// authenticate with a workload identity (IRSA, EKS Pod Identity, an
// instance role) instead of a static access key sitting in a secret.
func NewAWSKMS(ctx context.Context, keyID, region string) (*AWSKMS, error) {
	return NewAWSKMSFromConfig(ctx, AWSKMSConfig{KeyID: keyID, Region: region})
}

// NewAWSKMSFromConfig builds a KEK from a full configuration.
func NewAWSKMSFromConfig(ctx context.Context, cfg AWSKMSConfig) (*AWSKMS, error) {
	keyID := strings.TrimSpace(cfg.KeyID)
	region := strings.TrimSpace(cfg.Region)
	if keyID == "" {
		return nil, fmt.Errorf("%w: key id is empty", ErrKMSConfig)
	}
	if region == "" {
		return nil, fmt.Errorf("%w: region is empty", ErrKMSConfig)
	}
	a := &AWSKMS{
		client:     cfg.Client,
		keyID:      keyID,
		deployment: strings.TrimSpace(cfg.Deployment),
		ref:        awsKMSRef(keyID, region),
		timeout:    cfg.Timeout,
	}
	if a.timeout <= 0 {
		a.timeout = defaultKMSTimeout
	}
	if a.deployment == "" {
		a.deployment = a.ref
	}
	if a.client == nil {
		// LoadDefaultConfig reads the shared config, environment and any
		// container or instance credential endpoint. It can make a network
		// call (IMDS), hence the context.
		awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
		if err != nil {
			return nil, fmt.Errorf("load aws configuration: %w", err)
		}
		a.client = kms.NewFromConfig(awsCfg)
	}
	return a, nil
}

// Ref identifies the master key, in the shape the local provider uses, and
// is stored in data_keys.kek_ref so a wrapped key records which master key
// protects it. It must stay stable for the life of an installation:
// changing it strands every key wrapped under the old spelling, which is
// what RotateKEK exists to repair.
func (a *AWSKMS) Ref() string { return a.ref }

// Wrap encrypts a data key under the master key. It returns the KMS
// ciphertext blob unchanged, including its own key metadata, so the blob
// stays self-describing to AWS. Any failure returns an error and no
// bytes: there is no partial result a caller could mistake for a wrapped
// key, and the call is safe to retry because Encrypt has no side effect
// on this side.
func (a *AWSKMS) Wrap(ctx context.Context, dek []byte) ([]byte, error) {
	switch {
	case len(dek) == 0:
		return nil, errors.New("data key is empty")
	case len(dek) > kmsPlaintextLimit:
		return nil, fmt.Errorf("data key is %d bytes, over the kms plaintext limit of %d", len(dek), kmsPlaintextLimit)
	}
	callCtx, cancel := context.WithTimeout(ctx, a.timeout)
	defer cancel()
	out, err := a.client.Encrypt(callCtx, &kms.EncryptInput{
		KeyId:             &a.keyID,
		Plaintext:         dek,
		EncryptionContext: a.encryptionContext(),
	})
	if err != nil {
		return nil, a.callErr(ctx, "encrypt", err)
	}
	if len(out.CiphertextBlob) == 0 {
		return nil, fmt.Errorf("kms encrypt with %s returned an empty ciphertext", a.ref)
	}
	return out.CiphertextBlob, nil
}

// Unwrap decrypts a wrapped data key.
func (a *AWSKMS) Unwrap(ctx context.Context, wrapped []byte) ([]byte, error) {
	if len(wrapped) == 0 {
		return nil, ErrMalformed
	}
	callCtx, cancel := context.WithTimeout(ctx, a.timeout)
	defer cancel()
	out, err := a.client.Decrypt(callCtx, &kms.DecryptInput{
		CiphertextBlob: wrapped,
		// Naming the key is not optional here. Without KeyId, KMS takes the
		// key from metadata inside the blob, so anyone who can write to
		// data_keys.wrapped could substitute a blob made under a key they
		// control and this process would happily adopt a data key the
		// attacker knows. Pinning the key turns that into a decrypt failure.
		KeyId:             &a.keyID,
		EncryptionContext: a.encryptionContext(),
	})
	if err != nil {
		return nil, a.callErr(ctx, "decrypt", err)
	}
	if len(out.Plaintext) == 0 {
		return nil, fmt.Errorf("kms decrypt with %s returned an empty plaintext", a.ref)
	}
	return out.Plaintext, nil
}

// Verify proves the configured key can both encrypt and decrypt before
// any real key material depends on it. A caller runs it at start-up so a
// wrong key policy or a key pending deletion shows up as a boot failure
// rather than as the first tenant being unable to save a credential.
func (a *AWSKMS) Verify(ctx context.Context) error {
	probe := []byte("supermcp kms probe")
	wrapped, err := a.Wrap(ctx, probe)
	if err != nil {
		return err
	}
	got, err := a.Unwrap(ctx, wrapped)
	if err != nil {
		return err
	}
	if string(got) != string(probe) {
		return fmt.Errorf("kms key %s does not round-trip", a.ref)
	}
	return nil
}

// callErr wraps a failed KMS call, adding ErrKeyServiceUnavailable when
// the service was out of reach. ctx is the caller's context, not the one
// bounded by a.timeout: once the caller has given up, the failure says
// nothing about the service.
func (a *AWSKMS) callErr(ctx context.Context, op string, err error) error {
	if ctx.Err() == nil && kmsUnavailable(err) {
		return fmt.Errorf("kms %s with %s: %w: %w", op, a.ref, ErrKeyServiceUnavailable, err)
	}
	return fmt.Errorf("kms %s with %s: %w", op, a.ref, err)
}

// kmsUnavailable reports whether err is KMS, or the way to it, failing
// rather than refusing. The AWS SDK wraps a transport failure in a
// RequestSendError and a service answer in a ResponseError around an
// APIError, and its retryer keeps the last attempt's chain intact, so
// errors.As finds each however many attempts came before.
func kmsUnavailable(err error) bool {
	// The per-call timeout; callErr has ruled out the caller's own.
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var sendErr *smithyhttp.RequestSendError
	if errors.As(err, &sendErr) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	var respErr *smithyhttp.ResponseError
	if errors.As(err, &respErr) {
		code := respErr.HTTPStatusCode()
		if code >= http.StatusInternalServerError || code == http.StatusTooManyRequests {
			return true
		}
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.ErrorCode() {
		case "ThrottlingException", "DependencyTimeoutException", "KMSInternalException",
			"InternalFailure", "ServiceUnavailable", "RequestTimeout":
			return true
		}
		// KMSInvalidStateException, AccessDeniedException and
		// InvalidCiphertextException are client faults, so a disabled key,
		// a denying policy or a rejected blob stays a refusal.
		return apiErr.ErrorFault() == smithy.FaultServer
	}
	return false
}

// encryptionContext is the additional authenticated data KMS binds into
// every blob. It is not secret — CloudTrail records it, which is the
// point: a Decrypt call carrying the wrong context is both refused and
// visible in the audit trail.
//
// app and purpose give domain separation, so a blob produced for some
// other use of the same shared key cannot be fed back in as a data key.
// deployment is the one that matters for theft: a wrapped key copied out
// of production's database will not open in staging, even though both
// pods hold credentials for the same KMS key.
//
// A fresh map per call keeps the caller unable to mutate ours; wrapping
// happens once per data key, not per request, so the allocation is free.
func (a *AWSKMS) encryptionContext() map[string]string {
	return map[string]string{
		"app":        "supermcp",
		"purpose":    "data-key-wrap",
		"deployment": a.deployment,
	}
}

// awsKMSRef spells the reference stored beside every wrapped key. An ARN
// already carries its region, and repeating it would give one key two
// spellings and so two populations of data keys that look unrelated.
func awsKMSRef(keyID, region string) string {
	if strings.HasPrefix(keyID, "arn:") {
		return "awskms:" + keyID
	}
	return "awskms:" + region + "/" + keyID
}
