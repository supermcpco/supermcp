// Package invalidation carries cache invalidations between replicas.
//
// The authorisation evaluator and the data-loss policy reader each keep a
// short per-process cache. A write on one replica drops that replica's
// entries at once, but every other replica would go on answering from its
// own copy until the entry aged out. For a revoked role that is revoked
// access still working, so the database tells every replica instead.
//
// Triggers on the tables those caches read (migration 00020) call
// pg_notify on Channel with a payload of "<kind>:<organization id>", or
// "<kind>:*" for a row that belongs to no organisation. A notification
// sent inside a transaction is delivered only if it commits, and only
// once per distinct payload however many rows the transaction touched.
// Each replica holds one Listener, which drops the named organisation's
// entries from the caches registered for that kind.
//
// The time-to-live the caches already had stays as the backstop: when the
// listener is disconnected, entries still expire.
package invalidation

import (
	"strings"
)

// Channel is the Postgres notification channel. The migration that
// installs the triggers spells it too; the two must agree.
const Channel = "supermcp_cache"

// Kind names a cache. The values are what the triggers send and what the
// metrics are labelled with, so they are a closed set.
type Kind string

const (
	// KindAuthz is the authorisation evaluator's bindings and tool access
	// rules.
	KindAuthz Kind = "authz"
	// KindDLP is the data-loss prevention policies.
	KindDLP Kind = "dlp"
)

// Source says why an entry was dropped: the write happened on this
// replica, a notification said so, or the listener (re)connected and
// could have missed notifications while it was away.
type Source string

const (
	SourceLocal     Source = "local"
	SourceNotify    Source = "notify"
	SourceReconnect Source = "reconnect"
)

// allOrgs is the organisation part of a payload that names no single
// organisation, such as a change to a built-in role.
const allOrgs = "*"

// probeKind is the payload kind the listener sends itself to prove the
// connection still delivers. Every replica receives every probe and
// ignores it.
const probeKind = "probe"

// Cache is what the listener needs from a cache: drop one organisation's
// entries, or everything.
type Cache interface {
	InvalidateOrg(orgID string)
	InvalidateAll()
}

// Payload formats a notification payload, for tests and for any code that
// needs to send one by hand.
func Payload(kind Kind, orgID string) string {
	if orgID == "" {
		orgID = allOrgs
	}
	return string(kind) + ":" + orgID
}

// message is a parsed payload. all means every organisation; probe marks
// the listener's own liveness check, whose nonce is in orgID.
type message struct {
	kind  Kind
	orgID string
	all   bool
	probe bool
}

// parse reads a payload. Anything malformed parses as "every cache, every
// organisation": a notification this build cannot read is still a sign
// that something changed, and dropping too much costs one reload.
func parse(payload string) message {
	kind, org, ok := strings.Cut(payload, ":")
	if !ok || kind == "" {
		return message{all: true}
	}
	if kind == probeKind {
		return message{probe: true, orgID: org}
	}
	m := message{kind: Kind(kind), orgID: org}
	if org == "" || org == allOrgs {
		m.all = true
	}
	return m
}
