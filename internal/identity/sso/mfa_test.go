package sso

import (
	"slices"
	"strings"
	"testing"
)

func TestMFARuleSatisfied(t *testing.T) {
	t.Parallel()
	def := DefaultMFARule()
	okta := MFARule{ACR: []string{"phr", "urn:okta:loa:2fa:any"}}
	tests := []struct {
		name string
		rule MFARule
		amr  []string
		acr  string
		want bool
	}{
		{"no rule counts nothing", MFARule{}, []string{"pwd", "mfa"}, "phr", false},
		{"password only", def, []string{"pwd"}, "", false},
		{"mfa", def, []string{"pwd", "mfa"}, "", true},
		{"otp", def, []string{"pwd", "otp"}, "", true},
		{"hardware key", def, []string{"hwk"}, "", true},
		{"smart card", def, []string{"sc"}, "", true},
		{"software key alone is not in the default", def, []string{"swk"}, "", false},
		{"no amr", def, nil, "", false},
		{"acr match", okta, []string{"pwd"}, "phr", true},
		{"acr not listed", okta, []string{"pwd"}, "urn:okta:loa:1fa:pwd", false},
		{"empty acr never matches", MFARule{ACR: []string{""}}, nil, "", false},
		{"amr is case sensitive", def, []string{"MFA"}, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.rule.Satisfied(tt.amr, tt.acr); got != tt.want {
				t.Errorf("Satisfied(%v, %q) = %v, want %v", tt.amr, tt.acr, got, tt.want)
			}
		})
	}
}

func TestMFARuleNormalized(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("a", maxRuleValueLen+1)
	many := make([]string, maxRuleValues+1)
	for i := range many {
		many[i] = "v" + strings.Repeat("x", i)
	}
	tests := []struct {
		name    string
		in      MFARule
		want    MFARule
		wantErr string
	}{
		{"trims and drops repeats", MFARule{AMR: []string{" mfa", "mfa", "", "otp "}, ACR: []string{"phr", " phr"}},
			MFARule{AMR: []string{"mfa", "otp"}, ACR: []string{"phr"}}, ""},
		{"nil lists come back empty", MFARule{}, MFARule{AMR: []string{}, ACR: []string{}}, ""},
		{"pwd is refused", MFARule{AMR: []string{"mfa", "pwd"}}, MFARule{}, `"pwd"`},
		{"a value too long", MFARule{ACR: []string{long}}, MFARule{}, "longer than"},
		{"too many values", MFARule{AMR: many}, MFARule{}, "more than"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := tt.in.normalized()
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want one mentioning %s", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(got.AMR, tt.want.AMR) || !slices.Equal(got.ACR, tt.want.ACR) ||
				got.AMR == nil || got.ACR == nil {
				t.Errorf("normalized = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestReportedMethods(t *testing.T) {
	t.Parallel()
	many := make([]any, 0, maxMethods+4)
	for i := range maxMethods + 4 {
		many = append(many, "m"+strings.Repeat("x", i))
	}
	tests := []struct {
		name   string
		claims map[string]any
		want   []string
	}{
		{"absent", map[string]any{}, nil},
		{"not a list", map[string]any{"amr": "pwd mfa"}, nil},
		{"list", map[string]any{"amr": []any{"pwd", "mfa"}}, []string{"pwd", "mfa"}},
		{"empty list", map[string]any{"amr": []any{}}, []string{}},
		{"drops non-strings, repeats and oversize values",
			map[string]any{"amr": []any{"pwd", 7.0, "pwd", "", strings.Repeat("x", maxMethodLen+1), "otp"}},
			[]string{"pwd", "otp"}},
		{"bounded", map[string]any{"amr": many}, func() []string {
			out := make([]string, 0, maxMethods)
			for _, m := range many[:maxMethods] {
				out = append(out, m.(string))
			}
			return out
		}()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := reportedMethods(tt.claims)
			if !slices.Equal(got, tt.want) || (got == nil) != (tt.want == nil) {
				t.Errorf("reportedMethods = %#v, want %#v", got, tt.want)
			}
		})
	}
}
