package audit_test

import (
	"context"
	"encoding/json"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/supermcpco/supermcp/internal/audit"
)

// The payload of a tool call is the most dangerous thing the audit trail can
// hold: it is whatever the caller typed. These tests pin down what each of
// the four policies is allowed to keep.

// samplePayload carries one of each thing an organisation might be forbidden
// to store: a payment card, an email address, a field whose name announces a
// secret, and an API key buried in free text one level down.
func samplePayload() map[string]any {
	return map[string]any{
		"card":     "4111 1111 1111 1111",
		"contact":  "ada@example.com",
		"password": "hunter2",
		"attempts": float64(3),
		"dryRun":   true,
		"parent":   nil,
		"cc":       []any{"bob@example.org"},
		"request": map[string]any{
			"command": "deploy --token sk-live-0123456789abcdefghij",
			"note":    "ping bob@example.org when it lands",
		},
	}
}

// secrets are the substrings that must not survive any policy but "full".
var secrets = []string{"4111", "ada@example.com", "hunter2", "sk-live-", "bob@example.org"}

func TestApplyKeepsOnlyWhatThePolicyAllows(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		mode  audit.PayloadMode
		want  any
		leaks bool // whether the original values are meant to survive
	}{
		{
			// An organisation that must not retain caller data at all still
			// keeps the fact that the call happened; only the body goes.
			name: "none keeps nothing",
			mode: audit.PayloadNone,
			want: nil,
		},
		{
			// The default: enough to see which arguments were supplied and
			// what kind each was, and nothing the caller typed.
			name: "metadata keeps only the shape",
			mode: audit.PayloadMetadata,
			want: map[string]any{
				"card":     "string",
				"contact":  "string",
				"password": "string",
				"attempts": "number",
				"dryRun":   "boolean",
				"parent":   "null",
				"cc":       "array",
				"request":  "object",
			},
		},
		{
			// Masked is for investigations: the structure and the harmless
			// values survive so the call can be read, the sensitive parts do
			// not.
			name: "masked redacts the sensitive parts and keeps the structure",
			mode: audit.PayloadMasked,
			want: map[string]any{
				"card":     "<redacted>",
				"contact":  "<redacted>",
				"password": "<redacted>",
				"attempts": float64(3),
				"dryRun":   true,
				"parent":   nil,
				"cc":       []any{"<redacted>"},
				"request": map[string]any{
					"command": "deploy --token <redacted>",
					"note":    "ping <redacted> when it lands",
				},
			},
		},
		{
			// Full is an explicit, deliberate choice by the organisation.
			name:  "full keeps everything",
			mode:  audit.PayloadFull,
			want:  samplePayload(),
			leaks: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			gotIn, gotOut := audit.Apply(tc.mode, samplePayload(), samplePayload())
			if !reflect.DeepEqual(gotIn, tc.want) {
				t.Errorf("policy %q stored the input as:\n  %s\nwanted:\n  %s", tc.mode, render(t, gotIn), render(t, tc.want))
			}
			// Output is the tool's answer and can contain the same material,
			// so the same policy has to apply to it.
			if !reflect.DeepEqual(gotOut, tc.want) {
				t.Errorf("policy %q treats the tool's output differently from its input; it stored:\n  %s\nwanted:\n  %s",
					tc.mode, render(t, gotOut), render(t, tc.want))
			}

			stored := render(t, gotIn) + render(t, gotOut)
			for _, secret := range secrets {
				if strings.Contains(stored, secret) != tc.leaks {
					verb := "kept"
					if tc.leaks {
						verb = "dropped"
					}
					t.Errorf("policy %q %s %q; what it stored was:\n  %s", tc.mode, verb, secret, stored)
				}
			}
		})
	}
}

func TestApplyOnValuesThatAreNotObjects(t *testing.T) {
	t.Parallel()

	// A tool may take a bare string or an array. Those go through the same
	// path and must not be stored verbatim under a policy that forbids it.
	cases := []struct {
		name  string
		mode  audit.PayloadMode
		in    any
		want  any
		leaks string
	}{
		{name: "metadata reduces a string to its length", mode: audit.PayloadMetadata,
			in: "ada@example.com", want: map[string]any{"_type": "string", "_len": 15}, leaks: "ada@example.com"},
		{name: "metadata reduces an array to its length", mode: audit.PayloadMetadata,
			in: []any{"ada@example.com", "x"}, want: map[string]any{"_type": "array", "_len": 2}, leaks: "ada@example.com"},
		{name: "masked redacts inside a bare string", mode: audit.PayloadMasked,
			in: "mail ada@example.com", want: "mail <redacted>", leaks: "ada@example.com"},
		{name: "masked walks into an array", mode: audit.PayloadMasked,
			in: []any{"ada@example.com", float64(1)}, want: []any{"<redacted>", float64(1)}, leaks: "ada@example.com"},
		{name: "nil stays nil", mode: audit.PayloadMasked, in: nil, want: nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, _ := audit.Apply(tc.mode, tc.in, nil)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("policy %q stored %#v as:\n  %s\nwanted:\n  %s", tc.mode, tc.in, render(t, got), render(t, tc.want))
			}
			if tc.leaks != "" && strings.Contains(render(t, got), tc.leaks) {
				t.Errorf("policy %q kept %q out of %#v", tc.mode, tc.leaks, tc.in)
			}
		})
	}
}

func render(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("could not render %#v for the failure message: %v", v, err)
	}
	return string(b)
}

// ---------------------------------------------------------------------------
// diff.go

func TestChangesRecordsOnlyWhatDiffers(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		before     any
		after      any
		wantBefore map[string]any
		wantAfter  map[string]any
		wantNil    bool
	}{
		{
			// An admin who saves a form without touching it should not leave
			// a diff that looks like a change.
			name:    "identical objects are not a change",
			before:  map[string]any{"name": "prod", "port": float64(443)},
			after:   map[string]any{"name": "prod", "port": float64(443)},
			wantNil: true,
		},
		{
			name:       "a changed field appears on both sides, an untouched one on neither",
			before:     map[string]any{"name": "prod", "url": "https://old.example"},
			after:      map[string]any{"name": "prod", "url": "https://new.example"},
			wantBefore: map[string]any{"url": "https://old.example"},
			wantAfter:  map[string]any{"url": "https://new.example"},
		},
		{
			name:       "a new field appears only in after",
			before:     map[string]any{"name": "prod"},
			after:      map[string]any{"name": "prod", "timeout": float64(30)},
			wantBefore: map[string]any{},
			wantAfter:  map[string]any{"timeout": float64(30)},
		},
		{
			name:       "a removed field appears only in before",
			before:     map[string]any{"name": "prod", "timeout": float64(30)},
			after:      map[string]any{"name": "prod"},
			wantBefore: map[string]any{"timeout": float64(30)},
			wantAfter:  map[string]any{},
		},
		{
			name:       "a nested object that changed is recorded whole",
			before:     map[string]any{"auth": map[string]any{"kind": "none"}},
			after:      map[string]any{"auth": map[string]any{"kind": "oauth"}},
			wantBefore: map[string]any{"auth": map[string]any{"kind": "none"}},
			wantAfter:  map[string]any{"auth": map[string]any{"kind": "oauth"}},
		},
		{
			name:    "nothing on either side is no diff at all",
			before:  nil,
			after:   nil,
			wantNil: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := audit.Changes(tc.before, tc.after)
			if tc.wantNil {
				if got != nil {
					t.Fatalf("comparing %s with %s produced the diff %s; an event with no change should carry no diff",
						render(t, tc.before), render(t, tc.after), render(t, got))
				}
				return
			}
			if got == nil {
				t.Fatalf("comparing %s with %s produced no diff, but they differ; the change would be recorded as having no detail",
					render(t, tc.before), render(t, tc.after))
			}
			if !reflect.DeepEqual(got.Before, tc.wantBefore) {
				t.Errorf("the before side reads %s, wanted %s", render(t, got.Before), render(t, tc.wantBefore))
			}
			if !reflect.DeepEqual(got.After, tc.wantAfter) {
				t.Errorf("the after side reads %s, wanted %s", render(t, got.After), render(t, tc.wantAfter))
			}
		})
	}
}

func TestCreatedAndDeletedRecordOneSideOnly(t *testing.T) {
	t.Parallel()

	obj := map[string]any{"id": "c_1", "name": "prod"}

	created := audit.Created(obj)
	if created == nil {
		t.Fatalf("Created(%s) produced no diff; a creation event would record nothing about what was created", render(t, obj))
	}
	if len(created.Before) != 0 {
		t.Errorf("Created recorded a before side %s; nothing existed before a creation", render(t, created.Before))
	}
	if !reflect.DeepEqual(created.After, obj) {
		t.Errorf("Created recorded %s as the new state, wanted %s", render(t, created.After), render(t, obj))
	}

	deleted := audit.Deleted(obj)
	if deleted == nil {
		t.Fatalf("Deleted(%s) produced no diff; a deletion event would record nothing about what was removed", render(t, obj))
	}
	if len(deleted.After) != 0 {
		t.Errorf("Deleted recorded an after side %s; nothing exists after a deletion", render(t, deleted.After))
	}
	if !reflect.DeepEqual(deleted.Before, obj) {
		t.Errorf("Deleted recorded %s as the removed state, wanted %s", render(t, deleted.Before), render(t, obj))
	}

	// A value that cannot be read as an object has no fields to diff.
	if d := audit.Created("not an object"); d != nil {
		t.Errorf("Created on a bare string produced %s; there is nothing there to record", render(t, d))
	}
}

var digest = regexp.MustCompile(`^<redacted:[0-9a-f]{8}>$`)

func TestSecretFieldsBecomeDigests(t *testing.T) {
	t.Parallel()

	const (
		oldSecret = "sk-live-old-0123456789"
		newSecret = "sk-live-new-0123456789"
	)
	// A rotation is exactly the change an auditor needs to see, and exactly
	// the value nobody may keep. A digest satisfies both.
	got := audit.Changes(
		map[string]any{"name": "prod", "apiKey": oldSecret, "url": "https://old.example"},
		map[string]any{"name": "prod", "apiKey": newSecret, "url": "https://new.example"},
	)
	if got == nil {
		t.Fatal("rotating an API key produced no diff at all")
	}
	rendered := render(t, got)
	for _, secret := range []string{oldSecret, newSecret} {
		if strings.Contains(rendered, secret) {
			t.Fatalf("the diff stores the API key %q verbatim: %s", secret, rendered)
		}
	}
	beforeKey, _ := got.Before["apiKey"].(string)
	afterKey, _ := got.After["apiKey"].(string)
	if !digest.MatchString(beforeKey) || !digest.MatchString(afterKey) {
		t.Fatalf("apiKey reads as %q -> %q; a secret field should read as a <redacted:xxxxxxxx> digest so a reader can see it changed",
			beforeKey, afterKey)
	}
	if beforeKey == afterKey {
		t.Errorf("the old and the new API key both digest to %s, so the diff cannot show that the key was rotated", beforeKey)
	}
	// A field that names nothing sensitive is the administrator's own
	// configuration and is kept as given.
	if got.After["url"] != "https://new.example" {
		t.Errorf("the url field reads as %#v; only fields whose name names a secret should be redacted", got.After["url"])
	}

	// The digest has to be stable, or two unchanged deployments would look
	// like a rotation.
	first := audit.Created(map[string]any{"password": "same"})
	second := audit.Created(map[string]any{"password": "same"})
	if first.After["password"] != second.After["password"] {
		t.Errorf("the same secret digests to %v and then to %v; an unchanged value would look like a change",
			first.After["password"], second.After["password"])
	}
	if !digest.MatchString(first.After["password"].(string)) {
		t.Errorf("a field named \"password\" reads as %#v rather than a digest", first.After["password"])
	}
}

// ---------------------------------------------------------------------------
// Mode/SetMode round trip

func TestModeRoundTrip(t *testing.T) {
	ctx := context.Background()
	db := liveDB(ctx, t)

	// org_settings has a foreign key to organizations, so the policy needs a
	// real tenant to hang off.
	const org = "audit_t_policy"
	drop := func(ctx context.Context) {
		if err := db.Bypass(ctx, "audit policy test cleanup", func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `DELETE FROM organizations WHERE id = $1`, org)
			return err
		}); err != nil {
			t.Fatalf("could not remove the test organisation %s; a rerun will not be clean: %v", org, err)
		}
	}
	drop(ctx)
	if err := db.Bypass(ctx, "audit policy test seed", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO organizations (id, slug, name) VALUES ($1,$1,'audit policy test')`, org)
		return err
	}); err != nil {
		t.Fatalf("could not create the test organisation %s: %v", org, err)
	}
	t.Cleanup(func() { drop(context.WithoutCancel(ctx)) })

	p := audit.NewPolicies(db)

	// An organisation that has never chosen gets the conservative default,
	// not the most permissive one.
	if got := p.Mode(ctx, org); got != audit.DefaultPayloadMode {
		t.Errorf("an organisation with no stored policy reports %q; it should fall back to %q", got, audit.DefaultPayloadMode)
	}
	if got := p.Mode(ctx, ""); got != audit.DefaultPayloadMode {
		t.Errorf("Mode with no organisation reports %q; it should fall back to %q", got, audit.DefaultPayloadMode)
	}
	var nilPolicies *audit.Policies
	if got := nilPolicies.Mode(ctx, org); got != audit.DefaultPayloadMode {
		t.Errorf("Mode on a nil *Policies reports %q rather than %q; callers rely on the nil value behaving like the default", got, audit.DefaultPayloadMode)
	}

	for _, mode := range []audit.PayloadMode{audit.PayloadFull, audit.PayloadNone, audit.PayloadMasked, audit.PayloadMetadata} {
		if err := p.SetMode(ctx, org, mode); err != nil {
			t.Fatalf("storing the payload policy %q for %s failed: %v", mode, org, err)
		}
		// SetMode must invalidate its own cache, or an administrator's
		// change would appear to have been ignored for the next 30 seconds.
		if got := p.Mode(ctx, org); got != mode {
			t.Fatalf("the payload policy was set to %q but reads back as %q straight afterwards", mode, got)
		}
		// A second reader, with a cold cache, must agree.
		if got := audit.NewPolicies(db).Mode(ctx, org); got != mode {
			t.Errorf("the payload policy %q was not durable: a fresh reader sees %q", mode, got)
		}
	}

	if err := p.SetMode(ctx, org, audit.PayloadMode("everything")); err == nil {
		t.Error("SetMode accepted the payload policy \"everything\"; only none, metadata, masked and full are storable")
	}
	if got := p.Mode(ctx, org); got != audit.PayloadMetadata {
		t.Errorf("a rejected SetMode left the stored policy as %q; it should still be the last accepted value, %q", got, audit.PayloadMetadata)
	}
}
