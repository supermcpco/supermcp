package dlp_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/supermcpco/supermcp/internal/dlp"
	"github.com/supermcpco/supermcp/internal/store"
	"github.com/supermcpco/supermcp/internal/tenant"
)

// A detector that fires on everything is worse than none, so every case
// below carries its negatives: the order numbers, dates, version strings
// and identifiers a real estate is full of, which must produce nothing.

func only(t *testing.T, name string) dlp.Options {
	t.Helper()
	d, ok := dlp.Lookup(name)
	if !ok {
		t.Fatalf("no detector called %s", name)
	}
	return dlp.Options{Detectors: []dlp.Detector{d}}
}

func TestDetectors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		detector  string
		positives []string
		negatives []string
	}{
		{
			detector: dlp.DetectorPaymentCard,
			positives: []string{
				"4111111111111111",
				"4111 1111 1111 1111",
				"4111-1111-1111-1111",
				"card 5555555555554444 on file",
				"378282246310005",
				"6011111111111117",
			},
			negatives: []string{
				"1234567890123456",         // sixteen digits, fails Luhn
				"4111111111111112",         // one digit out
				"0000 0000 0000 0000",      // uniform, passes Luhn by accident
				"order ORD-2024-000123456", // an order number
				"12345678901234567890",     // a longer run: no card-shaped prefix
				"2024-01-15",
				"v1.2.3",
				"550e8400-e29b-41d4-a716-446655440000",
			},
		},
		{
			detector: dlp.DetectorIBAN,
			positives: []string{
				"DE89370400440532013000",
				"DE89 3704 0044 0532 0130 00",
				"GB82WEST12345698765432",
				"FR1420041010050500013M02606",
			},
			negatives: []string{
				"DE00370400440532013000", // check digits do not hold
				"DE8937040044053201300",  // right country, wrong length
				"DE123456789",            // a VAT number
				"SKU1234567890ABCDEFGH",
				"550e8400-e29b-41d4-a716-446655440000",
			},
		},
		{
			detector: dlp.DetectorEmail,
			positives: []string{
				"alice.smith+billing@example.co.uk",
				"write to a@b.io please",
			},
			negatives: []string{
				"root@localhost",
				"@channel please look",
				"see example.com for details",
				"npm i left-pad@1.2.3",
			},
		},
		{
			detector: dlp.DetectorPhone,
			positives: []string{
				"+49 30 123456",
				"+1 (555) 123-4567",
				"call 555-123-4567",
				"030 12345678",
			},
			negatives: []string{
				"1234567890",             // a bare run of digits
				"order 987654321012",     //
				"+123456789012345678",    // too long to be a number
				"2024-01-15",             // a date
				"1.2.3.4",                // a version
				"0000000000",             // uniform
				"4111 1111 1111 1111",    // a card, not a number
				"550e8400-e29b-41d4-a71", //
			},
		},
		{
			detector: dlp.DetectorUSSSN,
			positives: []string{
				"123-45-6789",
				"ssn 123 45 6789",
			},
			negatives: []string{
				"000-45-6789", // area never issued
				"666-45-6789",
				"900-45-6789",
				"123-00-6789", // group never issued
				"123-45-0000", // serial never issued
				"123456789",   // unseparated: an order number looks the same
				"2024-01-15",
			},
		},
		{
			detector: dlp.DetectorDETaxID,
			positives: []string{
				"36574261809",
				"Steuer-ID 36574261809 liegt vor",
			},
			negatives: []string{
				"12345678901",   // no digit repeats
				"36574261808",   // check digit is wrong
				"01234567890",   // no tax number begins with zero
				"1737059400000", // a timestamp in milliseconds
				"49301234567",   // a telephone number
			},
		},
		{
			detector: dlp.DetectorCredential,
			positives: []string{
				"ghp_" + strings.Repeat("a", 36),
				"xoxb-123456789012-abcdefghijkl",
				"sk_live_" + strings.Repeat("A", 24),
				"AKIAIOSFODNN7EXAMPLE",
				"AIza" + strings.Repeat("b", 35),
				"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk",
				"-----BEGIN RSA PRIVATE KEY-----",
				"Authorization: Bearer " + strings.Repeat("x", 32),
			},
			negatives: []string{
				"550e8400-e29b-41d4-a716-446655440000",                             // a UUID
				"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", // a content hash
				"dGhpcyBpcyBub3QgYSBzZWNyZXQ=",                                     // base64 prose
				"https://example.com/v1/orders/123456",
				"correlation id 7f3a9c2e5b1d4e8f",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.detector, func(t *testing.T) {
			t.Parallel()
			opt := only(t, tc.detector)
			for _, in := range tc.positives {
				res := dlp.Scan(in, opt)
				if res.Matches == 0 {
					t.Errorf("%s missed %q", tc.detector, in)
					continue
				}
				if got := res.Findings[0].Kind; got == "" {
					t.Errorf("%s reported no kind for %q", tc.detector, in)
				}
				if got := res.Findings[0].Confidence; got == "" {
					t.Errorf("%s reported no confidence for %q", tc.detector, in)
				}
			}
			for _, in := range tc.negatives {
				if res := dlp.Scan(in, opt); res.Matches != 0 {
					t.Errorf("%s fired on %q: %+v", tc.detector, in, res.Findings)
				}
			}
		})
	}
}

// A finding says where it was and how far it ran, and carries no part of
// what it found: an excerpt would put the value into whatever stores it.
func TestFindingLocatesWithoutQuoting(t *testing.T) {
	t.Parallel()
	in := map[string]any{"note": "charge 4111 1111 1111 1111 today"}
	res := dlp.Scan(in, only(t, dlp.DetectorPaymentCard))
	if res.Matches != 1 {
		t.Fatalf("matches = %d, want 1", res.Matches)
	}
	f := res.Findings[0]
	if f.Path != "$.note" {
		t.Errorf("path = %q, want $.note", f.Path)
	}
	if f.Start != 7 || f.End != 26 {
		t.Errorf("span = [%d,%d), want [7,26)", f.Start, f.End)
	}
	if f.Kind != dlp.KindPaymentCard || f.Confidence != dlp.ConfidenceHigh {
		t.Errorf("finding = %+v", f)
	}
}

// The detectors run over windows of the text rather than all of it, which
// is only sound if a window carries enough of its surroundings for a word
// boundary at the edge to be judged against the text. These are the cases
// that would break first if it did not.
func TestWindowsKeepTheirContext(t *testing.T) {
	t.Parallel()
	pad := strings.Repeat("filler words here. ", 40)

	tests := []struct {
		name     string
		detector string
		in       string
		want     int
	}{
		{name: "a card is a card at the start of the text", detector: dlp.DetectorPaymentCard,
			in: "4111111111111111 charged", want: 1},
		{name: "a card is a card at the end of the text", detector: dlp.DetectorPaymentCard,
			in: "charged 4111111111111111", want: 1},
		{name: "a card inside an identifier is not one", detector: dlp.DetectorPaymentCard,
			in: "ref4111111111111111", want: 0},
		{name: "nor with the identifier behind it", detector: dlp.DetectorPaymentCard,
			in: "4111111111111111ref", want: 0},
		{name: "an IBAN inside a word is not one", detector: dlp.DetectorIBAN,
			in: "XDE89370400440532013000", want: 0},
		{name: "a number far into a long text is still found", detector: dlp.DetectorPaymentCard,
			in: pad + "4111111111111111 " + pad, want: 1},
		{name: "two numbers in one window are both found", detector: dlp.DetectorPaymentCard,
			in: "4111111111111111 and 5555555555554444", want: 2},
		{name: "an address far into a long text is still found", detector: dlp.DetectorEmail,
			in: pad + "alice@example.com " + pad, want: 1},
		{name: "addresses close together are counted once each", detector: dlp.DetectorEmail,
			in: "a@b.io c@d.io e@f.io", want: 3},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			res := dlp.Scan(tc.in, only(t, tc.detector))
			if res.Matches != tc.want {
				t.Fatalf("matches = %d, want %d: %+v", res.Matches, tc.want, res.Findings)
			}
			// An offset is into the whole string, never into the window the
			// detector happened to search.
			for _, f := range res.Findings {
				if f.Start < 0 || f.End > len(tc.in) || f.Start >= f.End {
					t.Errorf("span [%d,%d) is not inside a string of %d", f.Start, f.End, len(tc.in))
					continue
				}
				if got := tc.in[f.Start:f.End]; strings.TrimSpace(got) == "" {
					t.Errorf("span [%d,%d) points at whitespace", f.Start, f.End)
				}
			}
		})
	}
}

func TestActions(t *testing.T) {
	t.Parallel()
	const card = "4111 1111 1111 1111"
	value := func() map[string]any {
		return map[string]any{
			"note":  "pay with " + card,
			"count": 3,
			"items": []any{map[string]any{"pan": card}},
		}
	}

	t.Run("allow passes the value through", func(t *testing.T) {
		t.Parallel()
		in := value()
		out, res, err := dlp.Apply(in, dlp.ActionAllow, dlp.Options{})
		if err != nil {
			t.Fatal(err)
		}
		if res.Matches != 2 {
			t.Fatalf("matches = %d, want 2", res.Matches)
		}
		m, ok := out.(map[string]any)
		if !ok || !strings.Contains(m["note"].(string), card) {
			t.Fatalf("allow changed the value: %#v", out)
		}
	})

	t.Run("mask replaces the match and leaves the original alone", func(t *testing.T) {
		t.Parallel()
		in := value()
		out, res, err := dlp.Apply(in, dlp.ActionMask, dlp.Options{})
		if err != nil {
			t.Fatal(err)
		}
		if res.Matches != 2 {
			t.Fatalf("matches = %d, want 2", res.Matches)
		}
		m := out.(map[string]any)
		if got := m["note"].(string); got != "pay with <redacted:payment_card>" {
			t.Errorf("note = %q", got)
		}
		nested := m["items"].([]any)[0].(map[string]any)
		if got := nested["pan"].(string); got != "<redacted:payment_card>" {
			t.Errorf("nested = %q", got)
		}
		if got := m["count"]; got != 3 {
			t.Errorf("count = %v, want the value it came in with", got)
		}
		// Masking must not reach back into what the caller handed over:
		// the argument map is also what the upstream call will use.
		if !strings.Contains(in["note"].(string), card) {
			t.Error("mask rewrote the caller's own map")
		}
		if !strings.Contains(in["items"].([]any)[0].(map[string]any)["pan"].(string), card) {
			t.Error("mask rewrote the caller's own nested map")
		}
	})

	t.Run("refuse stops the call and names the kinds", func(t *testing.T) {
		t.Parallel()
		out, res, err := dlp.Apply(value(), dlp.ActionRefuse, dlp.Options{})
		if !errors.Is(err, dlp.ErrRefused) {
			t.Fatalf("err = %v, want ErrRefused", err)
		}
		if out != nil {
			t.Errorf("refuse returned a value: %#v", out)
		}
		if !strings.Contains(err.Error(), "payment_card") {
			t.Errorf("err = %q, should name the kind", err)
		}
		if strings.Contains(err.Error(), "4111") {
			t.Errorf("err = %q, must not quote the value", err)
		}
		if res.Clean() {
			t.Error("result says clean after two matches")
		}
	})

	t.Run("refuse passes a clean value", func(t *testing.T) {
		t.Parallel()
		in := map[string]any{"note": "nothing to see"}
		out, res, err := dlp.Apply(in, dlp.ActionRefuse, dlp.Options{})
		if err != nil {
			t.Fatal(err)
		}
		if !res.Clean() {
			t.Errorf("result = %+v, want clean", res)
		}
		if out == nil {
			t.Error("refuse dropped a clean value")
		}
	})
}

// A field whose name says what it holds is redacted whatever is in it,
// which is the audit floor's rule, kept here so the two agree.
func TestSecretFieldName(t *testing.T) {
	t.Parallel()
	in := map[string]any{"api_key": "not-a-recognisable-shape", "note": "fine"}

	out, res, err := dlp.Apply(in, dlp.ActionMask, dlp.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Matches != 1 || res.Findings[0].Detector != dlp.DetectorSecretKey {
		t.Fatalf("findings = %+v", res.Findings)
	}
	if got := out.(map[string]any)["api_key"]; got != "<redacted:credential>" {
		t.Errorf("api_key = %v", got)
	}

	// Excluded, the same value is invisible: it has no shape to recognise.
	without, res2, err := dlp.Apply(in, dlp.ActionMask, only(t, dlp.DetectorCredential))
	if err != nil {
		t.Fatal(err)
	}
	if res2.Matches != 0 {
		t.Errorf("findings without secret_key = %+v", res2.Findings)
	}
	if got := without.(map[string]any)["api_key"]; got != in["api_key"] {
		t.Errorf("api_key = %v, want it untouched", got)
	}
}

func TestTruncationBoundary(t *testing.T) {
	t.Parallel()
	const card = "4111111111111111"
	pad := strings.Repeat("x", 40)

	tests := []struct {
		name          string
		value         any
		maxBytes      int
		wantMatches   int
		wantTruncated bool
		wantBytes     int
	}{
		{
			name:      "budget equal to the value is not truncation",
			value:     pad,
			maxBytes:  len(pad),
			wantBytes: len(pad),
		},
		{
			name:          "one byte short is",
			value:         pad,
			maxBytes:      len(pad) - 1,
			wantTruncated: true,
			wantBytes:     len(pad) - 1,
		},
		{
			name:        "a match inside the window is found",
			value:       card + pad,
			maxBytes:    len(card),
			wantMatches: 1,
			// The window ends exactly where the card does, so nothing was
			// left unread within it, but the value continues.
			wantTruncated: true,
			wantBytes:     len(card),
		},
		{
			name:          "a match past the window is not",
			value:         pad + card,
			maxBytes:      len(pad),
			wantTruncated: true,
			wantBytes:     len(pad),
		},
		{
			name:          "the budget is spent across strings, in order",
			value:         []any{pad, card},
			maxBytes:      len(pad) + 4,
			wantTruncated: true,
			wantBytes:     len(pad) + 4,
		},
		{
			name:        "a whole value under the budget is read whole",
			value:       []any{pad, card},
			maxBytes:    len(pad) + len(card),
			wantMatches: 1,
			wantBytes:   len(pad) + len(card),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			res := dlp.Scan(tc.value, dlp.Options{MaxBytes: tc.maxBytes})
			if res.Matches != tc.wantMatches {
				t.Errorf("matches = %d, want %d", res.Matches, tc.wantMatches)
			}
			if res.Truncated != tc.wantTruncated {
				t.Errorf("truncated = %v, want %v", res.Truncated, tc.wantTruncated)
			}
			if res.Bytes != tc.wantBytes {
				t.Errorf("bytes = %d, want %d", res.Bytes, tc.wantBytes)
			}
			if res.Clean() && tc.wantTruncated {
				t.Error("a truncated scan reported a clean bill of health")
			}
		})
	}
}

// A window that ends inside a rune backs off to the boundary rather than
// handing a detector half a character.
func TestTruncationKeepsRunesWhole(t *testing.T) {
	t.Parallel()
	in := strings.Repeat("ü", 8) // two bytes each
	res := dlp.Scan(in, dlp.Options{MaxBytes: 5})
	if res.Bytes != 4 {
		t.Errorf("bytes = %d, want 4", res.Bytes)
	}
	if !res.Truncated {
		t.Error("truncated = false")
	}
}

func TestSelectPrecedence(t *testing.T) {
	t.Parallel()
	org := dlp.ScanPolicy{ID: "org", Action: dlp.ActionAllow, Enabled: true}
	conn := dlp.ScanPolicy{ID: "conn", ConnectorID: "c1", Action: dlp.ActionMask, Enabled: true}
	other := dlp.ScanPolicy{ID: "other", ConnectorID: "c2", Action: dlp.ActionRefuse, Enabled: true}
	tool := dlp.ScanPolicy{ID: "tool", ConnectorID: "c1", ToolID: "t1", Action: dlp.ActionRefuse, Enabled: true}
	off := dlp.ScanPolicy{ID: "off", ConnectorID: "c1", ToolID: "t1", Action: dlp.ActionRefuse, Enabled: false}

	tests := []struct {
		name      string
		list      []dlp.ScanPolicy
		connector string
		tool      string
		want      string
		wantFound bool
	}{
		{name: "nothing configured", list: nil, connector: "c1", tool: "t1"},
		{name: "the organisation's rule applies by default", list: []dlp.ScanPolicy{org}, connector: "c1", tool: "t1", want: "org", wantFound: true},
		{name: "a connector's rule replaces it", list: []dlp.ScanPolicy{org, conn}, connector: "c1", tool: "t1", want: "conn", wantFound: true},
		{name: "a tool's rule replaces the connector's", list: []dlp.ScanPolicy{org, conn, tool}, connector: "c1", tool: "t1", want: "tool", wantFound: true},
		{name: "another connector's rule is not ours", list: []dlp.ScanPolicy{org, other}, connector: "c1", tool: "t1", want: "org", wantFound: true},
		{name: "a tool rule does not reach its sibling", list: []dlp.ScanPolicy{conn, tool}, connector: "c1", tool: "t2", want: "conn", wantFound: true},
		{name: "a disabled rule is not a rule", list: []dlp.ScanPolicy{conn, off}, connector: "c1", tool: "t1", want: "conn", wantFound: true},
		{name: "order in the list does not decide", list: []dlp.ScanPolicy{tool, conn, org}, connector: "c1", tool: "t1", want: "tool", wantFound: true},
		{name: "two rules of the same reach cannot disagree into permissiveness",
			list: []dlp.ScanPolicy{{ID: "a", Action: dlp.ActionAllow, Enabled: true}, {ID: "b", Action: dlp.ActionRefuse, Enabled: true}},
			want: "b", wantFound: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, ok := dlp.Select(tc.list, tc.connector, tc.tool)
			if ok != tc.wantFound {
				t.Fatalf("found = %v, want %v", ok, tc.wantFound)
			}
			if ok && got.ID != tc.want {
				t.Errorf("selected %s, want %s", got.ID, tc.want)
			}
		})
	}
}

func TestPolicyValidate(t *testing.T) {
	t.Parallel()
	ok := dlp.ScanPolicy{Name: "cards", Scan: dlp.StageBoth, Action: dlp.ActionMask}
	tests := []struct {
		name    string
		policy  dlp.ScanPolicy
		wantErr bool
	}{
		{name: "a whole rule", policy: ok},
		{name: "no name", policy: dlp.ScanPolicy{Scan: dlp.StageBoth, Action: dlp.ActionMask}, wantErr: true},
		{name: "no scan", policy: dlp.ScanPolicy{Name: "x", Action: dlp.ActionMask}, wantErr: true},
		{name: "no action", policy: dlp.ScanPolicy{Name: "x", Scan: dlp.StageResult}, wantErr: true},
		{name: "an invented detector", policy: dlp.ScanPolicy{Name: "x", Scan: dlp.StageBoth, Action: dlp.ActionMask,
			Detectors: []string{"palantir"}}, wantErr: true},
		{name: "a tool without its connector", policy: dlp.ScanPolicy{Name: "x", Scan: dlp.StageBoth,
			Action: dlp.ActionMask, ToolID: "t1"}, wantErr: true},
		{name: "a negative window", policy: dlp.ScanPolicy{Name: "x", Scan: dlp.StageBoth,
			Action: dlp.ActionMask, MaxBytes: -1}, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.policy.Validate()
			if tc.wantErr && !errors.Is(err, dlp.ErrInvalid) {
				t.Fatalf("err = %v, want ErrInvalid", err)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func TestPolicyCoversAndOptions(t *testing.T) {
	t.Parallel()
	p := dlp.ScanPolicy{Scan: dlp.StageResult, Detectors: []string{dlp.DetectorEmail}, MaxBytes: 128}
	if p.Covers(dlp.StageArguments) {
		t.Error("a result-only rule covered the arguments")
	}
	if !p.Covers(dlp.StageResult) {
		t.Error("a result-only rule did not cover the result")
	}
	opt := p.Options("$.result")
	if len(opt.Detectors) != 1 || opt.Detectors[0].Name() != dlp.DetectorEmail {
		t.Fatalf("detectors = %+v", opt.Detectors)
	}
	if opt.MaxBytes != 128 || opt.Root != "$.result" {
		t.Errorf("options = %+v", opt)
	}
	// An empty list is every built-in, not none: a policy that named no
	// detector and scanned for nothing would be a rule with no effect.
	if len(dlp.ScanPolicy{}.Options("$").Detectors) != 0 {
		t.Error("an empty list should leave the choice to the scan")
	}
	res := dlp.Scan("a@b.io", dlp.ScanPolicy{}.Options("$"))
	if res.Matches == 0 {
		t.Error("an empty detector list scanned for nothing")
	}
}

// --- the policy round trip, against a real database ------------------------

// Everything above is pure. This one wants Postgres, because what is being
// checked is the unique index, the tenant policy and the column types.
func TestPolicyRoundTrip(t *testing.T) {
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("DATABASE_URL not set")
	}
	ctx := t.Context()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	maint, err := store.Open(ctx, url, url, log, store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := maint.Migrate(ctx, true); err != nil {
		t.Fatal(err)
	}
	maint.Close()

	st, err := store.Open(ctx, url, url, log, store.Options{AppRole: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	db := &tenant.DB{App: st.App, Maint: st.Maint, Log: log}

	orgID := "dlp_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:16]
	connID, toolID := orgID+"_c", orgID+"_t"
	if err := db.Bypass(ctx, "test seed", func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO organizations (id, slug, name) VALUES ($1,$1,$1)`, orgID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO connectors (id, organization_id, name, transport, auth)
			VALUES ($1,$2,'test','{}','{}')`, connID, orgID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO tools (id, connector_id, organization_id, name, definition)
			VALUES ($1,$2,$3,'charge','{}')`, toolID, connID, orgID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = db.Bypass(context.Background(), "test cleanup", func(tx pgx.Tx) error {
			_, err := tx.Exec(context.Background(), `DELETE FROM organizations WHERE id = $1`, orgID)
			return err
		})
	})

	policies := dlp.NewPolicies(db, nil)

	orgRule, err := policies.Create(ctx, orgID, dlp.ScanPolicy{Name: "everything", Scan: dlp.StageBoth,
		Action: dlp.ActionMask, Enabled: true, Detectors: []string{dlp.DetectorEmail}})
	if err != nil {
		t.Fatalf("create the organisation's rule: %v", err)
	}
	toolRule, err := policies.Create(ctx, orgID, dlp.ScanPolicy{Name: "payments", Scan: dlp.StageResult,
		Action: dlp.ActionRefuse, Enabled: true, ConnectorID: connID, ToolID: toolID})
	if err != nil {
		t.Fatalf("create the tool's rule: %v", err)
	}

	// One rule per scope: the second attempt at the same scope is refused
	// rather than quietly becoming the one that wins.
	if _, err := policies.Create(ctx, orgID, dlp.ScanPolicy{Name: "another", Scan: dlp.StageBoth,
		Action: dlp.ActionAllow, Enabled: true}); !errors.Is(err, dlp.ErrInvalid) {
		t.Errorf("a second rule for the organisation: err = %v, want ErrInvalid", err)
	}

	// A scope in another tenant is not a scope here.
	if _, err := policies.Create(ctx, orgID, dlp.ScanPolicy{Name: "elsewhere", Scan: dlp.StageBoth,
		Action: dlp.ActionMask, Enabled: true, ConnectorID: "connector_from_another_org"}); !errors.Is(err, dlp.ErrInvalid) {
		t.Errorf("a rule naming another tenant's connector: err = %v, want ErrInvalid", err)
	}

	got, found, err := policies.Resolve(ctx, orgID, connID, toolID)
	if err != nil || !found {
		t.Fatalf("resolve: %v found=%v", err, found)
	}
	if got.ID != toolRule.ID || got.Action != dlp.ActionRefuse {
		t.Errorf("resolved %+v, want the tool's rule", got)
	}
	got, found, err = policies.Resolve(ctx, orgID, connID, "some_other_tool")
	if err != nil || !found {
		t.Fatalf("resolve: %v found=%v", err, found)
	}
	if got.ID != orgRule.ID || len(got.Detectors) != 1 || got.Detectors[0] != dlp.DetectorEmail {
		t.Errorf("resolved %+v, want the organisation's rule with its detector list", got)
	}

	// A change is visible to the next read, not to the next half-minute.
	if _, err := policies.Update(ctx, orgID, orgRule.ID, dlp.ScanPolicy{Name: "everything", Scan: dlp.StageArguments,
		Action: dlp.ActionAllow, Enabled: true}); err != nil {
		t.Fatalf("update: %v", err)
	}
	got, _, err = policies.Resolve(ctx, orgID, connID, "some_other_tool")
	if err != nil {
		t.Fatal(err)
	}
	if got.Action != dlp.ActionAllow || got.Scan != dlp.StageArguments {
		t.Errorf("resolved %+v after the update", got)
	}

	// Screen is what the tool-call path calls: the organisation's rule now
	// masks addresses in the arguments and leaves the result alone.
	scr, err := policies.Screen(ctx, orgID, connID, "some_other_tool", dlp.StageArguments,
		map[string]any{"to": "alice@example.com"})
	if err != nil {
		t.Fatalf("screen: %v", err)
	}
	if !scr.Applied || scr.ScanPolicy.ID != orgRule.ID {
		t.Fatalf("screened by %+v", scr.ScanPolicy)
	}
	if got := scr.Value.(map[string]any)["to"]; got != "alice@example.com" {
		t.Errorf("an allowing rule changed the value: %v", got)
	}
	if scr.Result.Matches != 1 || scr.Result.Findings[0].Path != "$.arguments.to" {
		t.Errorf("findings = %+v", scr.Result.Findings)
	}
	scr, err = policies.Screen(ctx, orgID, connID, "some_other_tool", dlp.StageResult,
		map[string]any{"to": "alice@example.com"})
	if err != nil {
		t.Fatalf("screen: %v", err)
	}
	if scr.Applied {
		t.Error("an arguments-only rule reached the result")
	}

	if err := policies.Record(ctx, orgID, dlp.Recording{
		InvocationID: uuid.NewString(), PolicyID: toolRule.ID, ConnectorID: connID, ToolID: toolID,
		ToolName: "charge", Stage: dlp.StageResult, Action: dlp.ActionRefuse,
		Result: dlp.Scan(map[string]any{"pan": "4111 1111 1111 1111", "also": "4111111111111111"},
			dlp.Options{Detectors: []dlp.Detector{mustLookup(t, dlp.DetectorPaymentCard)}}),
	}); err != nil {
		t.Fatalf("record: %v", err)
	}
	var matches int
	var paths []string
	if err := db.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT matches, paths FROM dlp_findings WHERE organization_id = $1`, orgID).
			Scan(&matches, &paths)
	}); err != nil {
		t.Fatalf("read back the findings: %v", err)
	}
	if matches != 2 || len(paths) != 2 {
		t.Errorf("stored matches=%d paths=%v, want two of each", matches, paths)
	}

	if err := policies.Delete(ctx, orgID, toolRule.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := policies.Get(ctx, orgID, toolRule.ID); !errors.Is(err, dlp.ErrNotFound) {
		t.Errorf("get after delete: err = %v, want ErrNotFound", err)
	}
}

func mustLookup(t *testing.T, name string) dlp.Detector {
	t.Helper()
	d, ok := dlp.Lookup(name)
	if !ok {
		t.Fatalf("no detector called %s", name)
	}
	return d
}

// BenchmarkScanTypicalResult is the shape of the request path in
// practice: a full window of a result that is mostly prose and
// identifiers, with a few real values in it.
func BenchmarkScanTypicalResult(b *testing.B) {
	body := `{"billing":{"email":"alice@example.com","phone":"+49 30 123456"}},`
	body += strings.Repeat(`{"id":"ord_01HQ8","status":"shipped","carrier":"DHL","weight":2.4,"items":[{"sku":"AB-9921","qty":2,"title":"Kettle, stainless"}],"updated":"2024-01-15T09:30:00Z"},`, 420)
	value := map[string]any{"result": body}
	b.ReportAllocs()
	for b.Loop() {
		if res := dlp.Scan(value, dlp.Options{}); res.Matches != 2 {
			b.Fatalf("matches = %d", res.Matches)
		}
	}
}

// BenchmarkScan is the adversarial end of the same measurement: a full
// window in which nearly every line holds a long number and an address,
// so no prefilter and no window skips anything.
func BenchmarkScan(b *testing.B) {
	body := strings.Repeat("order 2024-000123456 for alice@example.com, shipped 2024-01-15, ref 550e8400-e29b-41d4-a716-446655440000. ", 700)
	value := map[string]any{"result": body[:dlp.DefaultMaxBytes]}
	b.ReportAllocs()
	for b.Loop() {
		if res := dlp.Scan(value, dlp.Options{}); res.Bytes == 0 {
			b.Fatal("nothing scanned")
		}
	}
}

func BenchmarkScanSmallArguments(b *testing.B) {
	args := map[string]any{
		"customer": "Alice Smith",
		"email":    "alice@example.com",
		"note":     "refund for order 2024-000123456",
		"amount":   4200,
	}
	b.ReportAllocs()
	for b.Loop() {
		_ = dlp.Scan(args, dlp.Options{})
	}
}
