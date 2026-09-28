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
		{"unicode", "Zoë Ångström 李", "Zoë Ångström 李", true},
		{"emoji sequence", "Team 👩\u200d💻", "Team 👩\u200d💻", true},
		{"at the limit", strings.Repeat("é", MaxNameLength), strings.Repeat("é", MaxNameLength), true},
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
