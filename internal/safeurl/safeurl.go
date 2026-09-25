// Package safeurl turns a URL into something that may be shown, logged or
// recorded: where it points, without the credentials a URL so often
// carries.
package safeurl

import (
	"net/url"
	"strings"
)

// Masked replaces a path segment that looks like a credential.
const Masked = "***"

// tokenLen is the length above which a path segment that is not a plain
// word is taken for a credential. Webhook and bot tokens run from 24
// characters up; ids and names that belong in a path rarely pass 20.
const tokenLen = 20

// Display returns the scheme, host and path of raw. The query and the
// fragment are dropped, because query-string API keys and signed-URL
// signatures live there, and so is the user info. A path segment longer
// than 20 characters that holds a digit, or both upper and lower case
// letters, is replaced by Masked: Slack, Discord and Telegram put the
// token in the path. What does not parse as a URL is not shown at all.
func Display(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	segs := strings.Split(u.EscapedPath(), "/")
	for i, s := range segs {
		if looksLikeToken(s) {
			segs[i] = Masked
		}
	}
	out := u.Scheme + "://" + u.Host + strings.Join(segs, "/")
	if u.RawQuery != "" || u.ForceQuery {
		out += "?" + Masked
	}
	return out
}

func looksLikeToken(seg string) bool {
	if len(seg) <= tokenLen {
		return false
	}
	var digit, upper, lower bool
	for _, r := range seg {
		switch {
		case r >= '0' && r <= '9':
			digit = true
		case r >= 'A' && r <= 'Z':
			upper = true
		case r >= 'a' && r <= 'z':
			lower = true
		}
	}
	return digit || (upper && lower)
}
