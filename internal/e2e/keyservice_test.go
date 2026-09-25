package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/jackc/pgx/v5"

	"github.com/supermcpco/supermcp/internal/secrets"
	"github.com/supermcpco/supermcp/internal/tenant"
)

// kmsHost is in the transport error the fake returns, so the test can
// tell whether the AWS detail reached the client or the log.
const kmsHost = "kms.eu-west-1.amazonaws.com"

// switchKMS is a KMS client that works until it is taken down, and then
// fails every call the way the AWS SDK reports a connection it could not
// open. A blob is the plaintext behind a prefix: nothing here needs it to
// be secret.
type switchKMS struct {
	down atomic.Bool
}

func (k *switchKMS) unreachable(op string) error {
	return &smithy.OperationError{ServiceID: "KMS", OperationName: op, Err: &smithyhttp.RequestSendError{
		Err: &net.OpError{Op: "dial", Net: "tcp", Err: &net.DNSError{Err: "no such host", Name: kmsHost}},
	}}
}

func (k *switchKMS) Encrypt(_ context.Context, in *kms.EncryptInput, _ ...func(*kms.Options)) (*kms.EncryptOutput, error) {
	if k.down.Load() {
		return nil, k.unreachable("Encrypt")
	}
	return &kms.EncryptOutput{CiphertextBlob: append([]byte("fake:"), in.Plaintext...), KeyId: in.KeyId}, nil
}

func (k *switchKMS) Decrypt(_ context.Context, in *kms.DecryptInput, _ ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	if k.down.Load() {
		return nil, k.unreachable("Decrypt")
	}
	return &kms.DecryptOutput{Plaintext: bytes.TrimPrefix(in.CiphertextBlob, []byte("fake:")), KeyId: in.KeyId}, nil
}

// syncBuffer is a log destination the server's goroutines and the test
// can share.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestCredentialSaveWithKeyServiceDown saves a credential while the key
// service cannot be reached. The first secret a workspace stores mints
// its data key, which has to be wrapped by the key service, so the save
// cannot succeed; it must answer 503 naming the key service, keep the AWS
// detail out of the reply, and put it in the log with the request id.
func TestCredentialSaveWithKeyServiceDown(t *testing.T) {
	ctx := context.Background()
	client := &switchKMS{}
	kek, err := secrets.NewAWSKMSFromConfig(ctx, secrets.AWSKMSConfig{
		KeyID: "alias/supermcp-e2e", Region: "eu-west-1", Client: client,
	})
	if err != nil {
		t.Fatal(err)
	}
	var logs syncBuffer
	h := startWith(t, harnessOptions{kek: kek, log: slog.New(slog.NewJSONHandler(&logs, nil))})
	upstream, _ := fakeUpstream(t)

	admin := h.register(t, "E2E key service")
	t.Cleanup(func() {
		_ = h.db.Bypass(ctx, "e2e cleanup", func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `DELETE FROM organizations WHERE id = $1`, admin.Org.ID)
			return err
		})
	})
	// A connector with no credentials seals nothing, so the workspace has
	// no data key yet.
	in := testConnector(t, upstream.URL)
	in.Credentials = nil
	c, err := h.connectors.Create(tenant.WithOrg(ctx, admin.Org.ID), admin.Org.ID, in)
	if err != nil {
		t.Fatal(err)
	}

	client.down.Store(true)
	var problem struct {
		Status int    `json:"status"`
		Detail string `json:"detail"`
		Errors []any  `json:"errors"`
	}
	path := "/api/v1/connectors/" + c.ID + "/credentials"
	body := map[string]any{"credentials": map[string]string{"FAKE_KEY": "secret-value"}}
	if code := h.do(t, http.MethodPut, path, body, &problem); code != http.StatusServiceUnavailable {
		t.Fatalf("save with the key service down: %d %+v, want 503", code, problem)
	}
	if !strings.Contains(problem.Detail, "key service") {
		t.Errorf("detail %q does not name the key service", problem.Detail)
	}
	if len(problem.Errors) != 0 {
		t.Errorf("reply carries error details: %+v", problem.Errors)
	}
	reply, _ := json.Marshal(problem)
	for _, leak := range []string{kmsHost, "alias/supermcp-e2e", "awskms", "KMS", "Encrypt"} {
		if strings.Contains(string(reply), leak) {
			t.Errorf("reply %s leaks %q", reply, leak)
		}
	}
	if !strings.Contains(logs.String(), `"msg":"key service unavailable"`) ||
		!strings.Contains(logs.String(), kmsHost) || !strings.Contains(logs.String(), `"req_id":"`) {
		t.Errorf("log does not record the cause with a request id:\n%s", logs.String())
	}
	if _, err := h.connectors.Get(tenant.WithOrg(ctx, admin.Org.ID), admin.Org.ID, c.ID); err != nil {
		t.Fatal(err)
	}

	// Back up, the same save goes through.
	client.down.Store(false)
	if code := h.do(t, http.MethodPut, path, body, nil); code != http.StatusOK {
		t.Fatalf("save with the key service back: %d", code)
	}
}
