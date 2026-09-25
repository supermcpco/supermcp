package secrets

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// sdkErr shapes err the way the AWS SDK returns a service answer: an
// operation error around an HTTP response error around the API error.
func sdkErr(status int, err error) error {
	return &smithy.OperationError{
		ServiceID:     "KMS",
		OperationName: "Encrypt",
		Err: &smithyhttp.ResponseError{
			Response: &smithyhttp.Response{Response: &http.Response{StatusCode: status}},
			Err:      err,
		},
	}
}

// sendErr shapes err the way the AWS SDK returns a transport failure.
func sendErr(err error) error {
	return &smithy.OperationError{
		ServiceID:     "KMS",
		OperationName: "Encrypt",
		Err:           &smithyhttp.RequestSendError{Err: err},
	}
}

func TestAWSKMSUnavailableIsDistinguished(t *testing.T) {
	t.Parallel()
	dial := &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}
	tests := []struct {
		name        string
		err         error
		unavailable bool
	}{
		{"connection refused", sendErr(dial), true},
		{"dns failure", sendErr(&net.DNSError{Err: "no such host", Name: "kms.eu-west-1.amazonaws.com"}), true},
		{"bare net error", dial, true},
		{"internal error", sdkErr(500, &types.KMSInternalException{}), true},
		{"dependency timeout", sdkErr(503, &types.DependencyTimeoutException{}), true},
		{"throttled", sdkErr(400, &smithy.GenericAPIError{Code: "ThrottlingException"}), true},
		{"unmodelled 503", sdkErr(503, &smithy.GenericAPIError{Code: "ServiceUnavailable"}), true},
		{"invalid ciphertext", sdkErr(400, &types.InvalidCiphertextException{}), false},
		{"incorrect key", sdkErr(400, &types.IncorrectKeyException{}), false},
		{"access denied", sdkErr(400, &smithy.GenericAPIError{Code: "AccessDeniedException", Fault: smithy.FaultClient}), false},
		{"disabled key", sdkErr(400, &types.DisabledException{}), false},
		{"key pending deletion", sdkErr(400, &types.KMSInvalidStateException{}), false},
		{"key not found", sdkErr(400, &types.NotFoundException{}), false},
		{"unclassified", errKMSDown, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			c := newFakeKMS()
			k := testKMS(t, c, AWSKMSConfig{})
			wrapped, err := k.Wrap(ctx, bytes.Repeat([]byte{1}, dekLen))
			if err != nil {
				t.Fatalf("wrap: %v", err)
			}

			c.encErr, c.decErr = tt.err, tt.err
			_, wrapErr := k.Wrap(ctx, bytes.Repeat([]byte{1}, dekLen))
			_, unwrapErr := k.Unwrap(ctx, wrapped)
			for op, err := range map[string]error{"wrap": wrapErr, "unwrap": unwrapErr} {
				if got := errors.Is(err, ErrKeyServiceUnavailable); got != tt.unavailable {
					t.Errorf("%s: errors.Is(ErrKeyServiceUnavailable) = %v, want %v (err: %v)", op, got, tt.unavailable, err)
				}
				// The provider's own error stays reachable either way.
				if !errors.Is(err, tt.err) {
					t.Errorf("%s: lost the service error: %v", op, err)
				}
			}
		})
	}
}

func TestAWSKMSUnavailableThroughSealer(t *testing.T) {
	t.Parallel()
	c := newFakeKMS()
	c.encErr = sendErr(&net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")})
	s := New(testKMS(t, c, AWSKMSConfig{}), NewMemoryKeyStore())
	_, err := s.Seal(context.Background(), ScopeInstance, []byte("x"), AAD{})
	if !errors.Is(err, ErrKeyServiceUnavailable) {
		t.Fatalf("seal error = %v, want ErrKeyServiceUnavailable", err)
	}
}

// stallKMS never answers; each call waits for its context.
type stallKMS struct{}

func (stallKMS) Encrypt(ctx context.Context, _ *kms.EncryptInput, _ ...func(*kms.Options)) (*kms.EncryptOutput, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (stallKMS) Decrypt(ctx context.Context, _ *kms.DecryptInput, _ ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestAWSKMSTimeoutIsUnavailable(t *testing.T) {
	t.Parallel()
	k, err := NewAWSKMSFromConfig(context.Background(), AWSKMSConfig{
		KeyID: "alias/supermcp", Region: "eu-west-1", Client: stallKMS{}, Timeout: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = k.Wrap(context.Background(), bytes.Repeat([]byte{1}, dekLen))
	if !errors.Is(err, ErrKeyServiceUnavailable) {
		t.Fatalf("per-call timeout: err = %v, want ErrKeyServiceUnavailable", err)
	}

	// A caller that has already gone says nothing about the service.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = k.Unwrap(ctx, []byte("blob"))
	if errors.Is(err, ErrKeyServiceUnavailable) {
		t.Fatalf("cancelled caller: err = %v, want no ErrKeyServiceUnavailable", err)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled caller: err = %v, want context.Canceled", err)
	}

	dctx, dcancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer dcancel()
	if _, err := k.Unwrap(dctx, []byte("blob")); errors.Is(err, ErrKeyServiceUnavailable) {
		t.Fatalf("caller past its deadline: err = %v, want no ErrKeyServiceUnavailable", err)
	}
}
