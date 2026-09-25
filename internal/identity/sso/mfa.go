package sso

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// MFARule says which of an OpenID Connect provider's answers count as a
// second factor. It is compared with the verified ID token only: the user
// endpoint's answer is not signed, and a claim missing from the token is
// not looked for anywhere else. A sign-in counts when the token's amr
// names any value in AMR, or its acr is one of ACR. Both empty is no
// rule, and then no sign-in counts.
type MFARule struct {
	AMR []string `json:"amr" required:"false" doc:"Authentication method references (RFC 8176) any of which, in the ID token's amr claim, counts as a second factor. pwd is refused."`
	ACR []string `json:"acr" required:"false" doc:"Authentication context class references any of which, as the ID token's acr claim, counts as a second factor."`
}

// DefaultMFARule is the rule a new OpenID Connect provider gets when its
// configuration names none: the amr values mfa, otp, hwk and sc. mfa says
// a second factor outright. otp, hwk and sc name factors a provider asks
// for beside a password, or which carry one of their own (a smart card
// has a PIN). swk is left out: a software key sits in the device's files,
// so a passkey held that way and used alone is one factor, and RFC 8176
// does not say otherwise.
func DefaultMFARule() MFARule {
	return MFARule{AMR: []string{"mfa", "otp", "hwk", "sc"}, ACR: []string{}}
}

// Limits on what a rule and a reported sign-in may hold. A provider
// controls what it reports, so a session keeps a bounded amount of it.
const (
	maxRuleValues   = 32
	maxRuleValueLen = 256
	maxMethods      = 16
	maxMethodLen    = 64
)

// Empty reports whether the rule counts nothing.
func (r MFARule) Empty() bool { return len(r.AMR) == 0 && len(r.ACR) == 0 }

// Satisfied reports whether a sign-in whose verified ID token carried amr
// and acr had a second factor under this rule.
func (r MFARule) Satisfied(amr []string, acr string) bool {
	for _, m := range amr {
		if slices.Contains(r.AMR, m) {
			return true
		}
	}
	return acr != "" && slices.Contains(r.ACR, acr)
}

// normalized trims the values, drops empty ones and repeats, and refuses a
// rule that is too long or would count a password as a second factor.
func (r MFARule) normalized() (MFARule, error) {
	amr, err := cleanRuleValues("amr", r.AMR)
	if err != nil {
		return MFARule{}, err
	}
	if slices.Contains(amr, "pwd") {
		return MFARule{}, errors.New(`mfa.amr cannot contain "pwd": a password is the first factor, not a second one`)
	}
	acr, err := cleanRuleValues("acr", r.ACR)
	if err != nil {
		return MFARule{}, err
	}
	return MFARule{AMR: amr, ACR: acr}, nil
}

func cleanRuleValues(field string, in []string) ([]string, error) {
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" || slices.Contains(out, v) {
			continue
		}
		if len(v) > maxRuleValueLen {
			return nil, fmt.Errorf("an mfa.%s value is longer than %d characters", field, maxRuleValueLen)
		}
		out = append(out, v)
	}
	if len(out) > maxRuleValues {
		return nil, fmt.Errorf("mfa.%s holds more than %d values", field, maxRuleValues)
	}
	return out, nil
}

// reportedMethods is the amr claim of a verified ID token as a session
// keeps it: strings only, without repeats, and bounded. Nil when the token
// carried no amr.
func reportedMethods(claims map[string]any) []string {
	list, ok := claims["amr"].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(list))
	for _, e := range list {
		s, ok := e.(string)
		if !ok || s == "" || len(s) > maxMethodLen || slices.Contains(out, s) {
			continue
		}
		out = append(out, s)
		if len(out) == maxMethods {
			break
		}
	}
	return out
}
