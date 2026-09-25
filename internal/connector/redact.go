package connector

import (
	"regexp"
	"strings"
	"unicode"
)

// A connector's auth and transport are meant to hold only {{env.*}}
// references, with the values sealed as credentials. They do not always:
// a provider-rotated refresh token configured as a literal stays in auth
// (see RotateRefreshToken), an imported document can carry a key, and a
// DSN or base URL can carry a password. So whatever shows them, the API,
// the audit diff, the re-sync preview and the revision history, shows
// them through RedactConfig.
//
// Only what is shown is redacted. What is stored stays as it is, and no
// endpoint accepts auth or transport from a client, so a redacted value
// can never be written back.

// Redacted replaces a secret value.
const Redacted = "***"

// RedactConfig returns a copy of v, a connector's auth or transport decoded
// into generic JSON values, with every secret replaced by Redacted, at any
// depth:
//
//   - the value of a key that names a secret (password, secret, token,
//     value, apiKey, key, credentials, authorization, cookie, and keys
//     ending in password, secret, token, apiKey or privateKey, such as
//     clientSecret, refreshToken or X-Auth-Token); a nested object or list
//     there has each of its values redacted
//   - the password in a URL or DSN (scheme://user:pass@host and
//     user:pass@tcp(host)), in a key=value connection string
//     (password=..., pwd=...), and the value of a query parameter whose
//     name names a secret
//
// Empty strings stay empty, so a reader can still tell a value was never
// set. v itself is not changed.
func RedactConfig(v any) any {
	return redact(v, false)
}

func redact(v any, secret bool) any {
	switch x := v.(type) {
	case nil:
		return nil
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			out[k] = redact(val, secret || secretKey(k))
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, val := range x {
			out[i] = redact(val, secret)
		}
		return out
	case string:
		if secret {
			if x == "" {
				return ""
			}
			return Redacted
		}
		return redactString(x)
	}
	// A number or a boolean.
	if secret {
		return Redacted
	}
	return v
}

// secretKey reports whether a key names a secret. It ignores case and the
// separators header and parameter names use.
func secretKey(k string) bool {
	n := strings.Map(func(r rune) rune {
		if r == '-' || r == '_' || r == ' ' || r == '.' {
			return -1
		}
		return unicode.ToLower(r)
	}, k)
	switch n {
	case "password", "passwd", "pwd", "secret", "token", "value", "apikey", "key", "credentials",
		"authorization", "proxyauthorization", "cookie", "setcookie":
		return true
	}
	for _, suffix := range []string{"password", "secret", "token", "apikey", "privatekey", "authorization"} {
		if strings.HasSuffix(n, suffix) {
			return true
		}
	}
	return false
}

var (
	// scheme://user:pass@host. The password runs to the last @ before any
	// white space, so one with an unescaped slash is still covered.
	reURLUserinfo = regexp.MustCompile(`([A-Za-z][A-Za-z0-9+.\-]*://)([^:@/\s]*):([^@\s]*)@`)
	// user:pass@tcp(host)/db, the Go MySQL form, at the start of a string
	// that has no scheme.
	reBareUserinfo = regexp.MustCompile(`^([^:@/\s]+):([^@\s]*)@`)
	// password=... in a key=value connection string.
	reKeywordPassword = regexp.MustCompile(`(?i)\b(password|pwd)(\s*=\s*)('[^']*'|"[^"]*"|[^;\s]+)`)
	// name=value in a query string.
	reQueryParam = regexp.MustCompile(`([?&])([^=&#\s]+)=([^&#\s]+)`)
)

func redactString(s string) string {
	if strings.Contains(s, "://") {
		s = reURLUserinfo.ReplaceAllString(s, "${1}${2}:"+Redacted+"@")
	} else {
		s = reBareUserinfo.ReplaceAllString(s, "${1}:"+Redacted+"@")
	}
	s = reKeywordPassword.ReplaceAllString(s, "${1}${2}"+Redacted)
	return reQueryParam.ReplaceAllStringFunc(s, func(m string) string {
		parts := reQueryParam.FindStringSubmatch(m)
		if !secretKey(parts[2]) {
			return m
		}
		return parts[1] + parts[2] + "=" + Redacted
	})
}
