package audit

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

// The signature is a wire format: a receiver that verifies deliveries has
// to be changed in step with it, so these vectors are fixed on purpose.
func TestSignDelivery(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		secret string
		ts     int64
		body   string
		want   string
	}{
		{"one record", "s3cr3t", 1700000000, "{\"seq\":1}\n", "c9b9279b89c2633f62612858197eb045e5426b86c95acf086506a450134e266d"},
		{"a second later", "s3cr3t", 1700000001, "{\"seq\":1}\n", "c84fe0fadc1c7784e82dc9b93b69fb02c2a23f9e31f0f485f5eb580c2a60861d"},
		{"another secret", "other", 1700000000, "{\"seq\":1}\n", "932436301812262359b19fc8d4b1d274fc1464b94aa7668cb05986dd42ae032b"},
		{"empty body", "s3cr3t", 1700000000, "", "f63f1341b06e485fe1fe78cbfd5f6d4cee0d492c21bbc3333af817254d0db38a"},
		{"no secret", "", 0, "x", "700eecec9dab1af0c68c5faed9ec417f29e96e084d7a08de14d545c02b0cbc55"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := SignDelivery(tc.secret, tc.ts, []byte(tc.body)); got != tc.want {
				t.Fatalf("signature = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestShipCursor(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		events   int
		statuses []int // one per request; the last repeats
		sendErr  bool  // the transport refuses every request
		wantReqs int
		wantSent int // records the receiver was handed
		wantSeq  int64
		wantErr  bool
	}{
		{name: "nothing to ship", events: 0, wantReqs: 0, wantSeq: 0},
		{name: "one partial batch", events: 3, statuses: []int{202}, wantReqs: 1, wantSent: 3, wantSeq: 3},
		{name: "exactly one batch", events: exportBatch, statuses: []int{200}, wantReqs: 1, wantSent: exportBatch, wantSeq: exportBatch},
		{name: "two batches", events: exportBatch + 7, statuses: []int{200}, wantReqs: 2, wantSent: exportBatch + 7, wantSeq: exportBatch + 7},
		{name: "rejected batch leaves the cursor alone", events: 10, statuses: []int{500}, wantReqs: 1, wantSent: 10, wantSeq: 0, wantErr: true},
		{name: "rejected retries from the last commit", events: exportBatch + 7, statuses: []int{200, 503}, wantReqs: 2, wantSent: exportBatch + 7, wantSeq: exportBatch, wantErr: true},
		{name: "transport error leaves the cursor alone", events: 5, sendErr: true, wantReqs: 1, wantSent: 5, wantSeq: 0, wantErr: true},
		{name: "a run is bounded", events: exportBatch * (exportMaxBatches + 2), statuses: []int{200},
			wantReqs: exportMaxBatches, wantSent: exportBatch * exportMaxBatches, wantSeq: exportBatch * exportMaxBatches},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			src := &sliceSource{records: records(tc.events)}
			client := &fakeDoer{statuses: tc.statuses, err: tc.sendErr}
			d := &delivery{dest: webhook(client, "s3cr3t")}

			err := d.ship(context.Background(), 0, src)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ship error = %v, want error %v", err, tc.wantErr)
			}
			if len(client.bodies) != tc.wantReqs {
				t.Fatalf("requests = %d, want %d", len(client.bodies), tc.wantReqs)
			}
			if src.cursor != tc.wantSeq {
				t.Fatalf("cursor = %d, want %d", src.cursor, tc.wantSeq)
			}
			sent := 0
			for i, body := range client.bodies {
				lines := countLines(body)
				sent += lines
				if lines > exportBatch {
					t.Fatalf("request %d carried %d records, over the batch size", i, lines)
				}
				verifySignature(t, client.headers[i], body, "s3cr3t")
			}
			if sent != tc.wantSent {
				t.Fatalf("records delivered = %d, want %d", sent, tc.wantSent)
			}
		})
	}
}

// A retry after a rejection must start from the cursor, not from where the
// failed batch ended, or the gap is lost for good.
func TestShipResumesAfterFailure(t *testing.T) {
	t.Parallel()
	src := &sliceSource{records: records(exportBatch + 4)}
	first := &fakeDoer{statuses: []int{200, 500}}
	d := &delivery{dest: webhook(first, "k")}
	if err := d.ship(context.Background(), 0, src); err == nil {
		t.Fatal("expected the second batch to be reported as rejected")
	}
	if src.cursor != exportBatch {
		t.Fatalf("cursor = %d, want %d", src.cursor, exportBatch)
	}

	second := &fakeDoer{statuses: []int{200}}
	d.dest = webhook(second, "k")
	if err := d.ship(context.Background(), src.cursor, src); err != nil {
		t.Fatalf("second run: %v", err)
	}
	if src.cursor != exportBatch+4 {
		t.Fatalf("cursor = %d, want %d", src.cursor, exportBatch+4)
	}
	if n := countLines(second.bodies[0]); n != 4 {
		t.Fatalf("resent %d records, want the 4 that were never accepted", n)
	}
}

func TestFilterCategories(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		filter string
		want   []string
	}{
		{"no filter", "", nil},
		{"null", "null", nil},
		{"empty object", "{}", nil},
		{"empty list means everything", `{"categories":[]}`, nil},
		{"two categories", `{"categories":["auth","admin"]}`, []string{"auth", "admin"}},
		{"malformed", `{"categories":"auth"}`, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := filterCategories([]byte(tc.filter))
			if len(got) != len(tc.want) {
				t.Fatalf("categories = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("categories = %v, want %v", got, tc.want)
				}
			}
		})
	}
}

// --- helpers ---

// webhook builds the signed-webhook destination these tests ship through.
func webhook(client Doer, secret string) destination {
	return &webhookDest{ep: Endpoint{Kind: KindWebhook, URL: "https://receiver.example/audit", Secret: secret}, client: client}
}

type sliceSource struct {
	records []Record
	cursor  int64
}

func (s *sliceSource) After(_ context.Context, afterSeq int64, limit int) ([]Record, error) {
	out := make([]Record, 0, limit)
	for i := range s.records {
		if s.records[i].Seq <= afterSeq {
			continue
		}
		out = append(out, s.records[i])
		if len(out) == limit {
			break
		}
	}
	return out, nil
}

func (s *sliceSource) Commit(_ context.Context, seq int64) error {
	if seq > s.cursor {
		s.cursor = seq
	}
	return nil
}

type fakeDoer struct {
	statuses []int
	err      bool
	bodies   [][]byte
	headers  []http.Header
}

func (f *fakeDoer) Do(req *http.Request) (*http.Response, error) {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	f.bodies = append(f.bodies, body)
	f.headers = append(f.headers, req.Header.Clone())
	if f.err {
		return nil, errors.New("dial refused")
	}
	status := 200
	if len(f.statuses) > 0 {
		i := len(f.bodies) - 1
		if i >= len(f.statuses) {
			i = len(f.statuses) - 1
		}
		status = f.statuses[i]
	}
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader("no"))}, nil
}

func records(n int) []Record {
	out := make([]Record, n)
	for i := range out {
		out[i] = Record{Seq: int64(i + 1), ID: fmt.Sprintf("evt-%d", i+1), Category: CategoryAuth, Action: "session.create", Outcome: Success}
	}
	return out
}

func countLines(body []byte) int {
	if len(body) == 0 {
		return 0
	}
	return bytes.Count(body, []byte("\n"))
}

func verifySignature(t *testing.T, h http.Header, body []byte, secret string) {
	t.Helper()
	ts, err := strconv.ParseInt(h.Get(TimestampHeader), 10, 64)
	if err != nil {
		t.Fatalf("timestamp header %q: %v", h.Get(TimestampHeader), err)
	}
	if want := SignDelivery(secret, ts, body); h.Get(SignatureHeader) != want {
		t.Fatalf("signature header = %s, want %s", h.Get(SignatureHeader), want)
	}
	// The timestamp is signed, so the same body under a neighbouring
	// timestamp must not verify.
	if h.Get(SignatureHeader) == SignDelivery(secret, ts+1, body) {
		t.Fatal("the signature does not cover the timestamp")
	}
}
