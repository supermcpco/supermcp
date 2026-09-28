package identity

import (
	"errors"
	"strings"
	"testing"
)

func TestCleanName(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want string
		ok   bool
	}{
		{"plain", "Ada Lovelace", "Ada Lovelace", true},
		{"trimmed", "  Ada \t", "Ada", true},
		{"unicode", "Zo\u00eb \u00c5ngstr\u00f6m \u674e", "Zo\u00eb \u00c5ngstr\u00f6m \u674e", true},
		{"nfc", "Zoe\u0308", "Zo\u00eb", true},
		{"nfc before counting", strings.Repeat("e\u0301", MaxNameLength), strings.Repeat("\u00e9", MaxNameLength), true},
		{"emoji zwj sequence", "Team \U0001F469\u200d\U0001F4BB", "Team \U0001F469\u200d\U0001F4BB", true},
		{"zero-width non-joiner", "\u0645\u06cc\u200c\u062e\u0648\u0627\u0647\u0645", "\u0645\u06cc\u200c\u062e\u0648\u0627\u0647\u0645", true},
		{"variation selector after a symbol", "\u2764\ufe0f Ops", "\u2764\ufe0f Ops", true},
		{"hangul filler beside letters", "Ada\u3164", "Ada\u3164", true},
		{"ideographic space inside", "\u5c71\u3000\u7530", "\u5c71\u3000\u7530", true},
		{"at the limit", strings.Repeat("\u00e9", MaxNameLength), strings.Repeat("\u00e9", MaxNameLength), true},
		{"limit after trimming", " " + strings.Repeat("a", MaxNameLength) + " ", strings.Repeat("a", MaxNameLength), true},
		{"empty", "", "", false},
		{"blank", "   \t ", "", false},
		{"too long", strings.Repeat("a", MaxNameLength+1), "", false},
		{"newline inside", "Ada\nLovelace", "", false},
		{"nul", "Ada\x00", "", false},
		{"escape", "Ada\x1b[31m", "", false},
		{"del", "Ada\x7f", "", false},
		{"c1 control", "Ada\u0085x", "", false},
		{"bidi override", "Ada\u202egnirts", "", false},
		{"bidi isolate", "\u2066Ada", "", false},
		{"arabic letter mark", "Ada\u061c", "", false},
		{"zero-width space inside", "Ada\u200bLovelace", "", false},
		{"soft hyphen", "Ada\u00adLovelace", "", false},
		{"byte order mark", "\ufeffAda", "", false},
		{"line separator", "Ada\u2028Lovelace", "", false},
		{"paragraph separator", "Ada\u2029Lovelace", "", false},
		{"private use", "Ada\ue000", "", false},
		{"unassigned", "Ada\u0378", "", false},
		{"zero-width space alone", "\u200b", "", false},
		{"zero-width joiner alone", "\u200d", "", false},
		{"hangul filler alone", "\u3164", "", false},
		{"hangul choseong filler alone", "\u115f", "", false},
		{"halfwidth hangul filler alone", "\uffa0", "", false},
		{"blank braille alone", "\u2800\u2800", "", false},
		{"variation selector alone", "\ufe0f", "", false},
		{"combining grapheme joiner alone", "\u034f", "", false},
		{"invalid utf-8", "Ada\xff", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			got, err := CleanName(c.in)
			if c.ok {
				if err != nil || got != c.want {
					t.Fatalf("CleanName(%q) = %q, %v; want %q", c.in, got, err, c.want)
				}
				return
			}
			if !errors.Is(err, ErrInvalidName) {
				t.Fatalf("CleanName(%q) = %q, %v; want ErrInvalidName", c.in, got, err)
			}
		})
	}
}

func TestCleanField(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, field, in, want string
		ok                    bool
	}{
		{"absent", "name", "", "", true},
		{"blank is absent", "orgName", "  ", "", true},
		{"clean", "orgName", " Acme ", "Acme", true},
		{"refused names its field", "orgName", "\u200b", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			got, err := cleanField(c.field, c.in)
			if c.ok {
				if err != nil || got != c.want {
					t.Fatalf("cleanField(%q) = %q, %v; want %q", c.in, got, err, c.want)
				}
				return
			}
			var field *InvalidNameError
			if !errors.As(err, &field) || field.Field != c.field || !errors.Is(err, ErrInvalidName) {
				t.Fatalf("cleanField(%q) = %v; want an InvalidNameError for %s", c.in, err, c.field)
			}
		})
	}
}

func TestProviderName(t *testing.T) {
	t.Parallel()
	if got := ProviderName("  Ada  "); got != "Ada" {
		t.Errorf("ProviderName kept %q", got)
	}
	if got := ProviderName("Ada\u202e"); got != "" {
		t.Errorf("ProviderName kept a refused name as %q", got)
	}
}
