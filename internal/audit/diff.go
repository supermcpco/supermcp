package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
)

// An admin event records what changed, not just that something did. The
// values are the administrator's own configuration, so they are stored as
// given, except where a field names a secret: those become a short digest,
// which is enough to see that a value changed without storing it.

// Diff is the before-and-after of one change.
type Diff struct {
	Before map[string]any `json:"before,omitempty"`
	After  map[string]any `json:"after,omitempty"`
}

// Changes builds a diff of the fields that differ between two values.
// Both are marshalled through JSON first, so a caller can pass the same
// structs the API serves.
func Changes(before, after any) *Diff {
	b, a := toMap(before), toMap(after)
	if b == nil && a == nil {
		return nil
	}
	d := &Diff{Before: map[string]any{}, After: map[string]any{}}
	seen := map[string]bool{}
	for k, bv := range b {
		seen[k] = true
		av, ok := a[k]
		if ok && reflect.DeepEqual(bv, av) {
			continue
		}
		d.Before[k] = redactValue(k, bv)
		if ok {
			d.After[k] = redactValue(k, av)
		}
	}
	for k, av := range a {
		if seen[k] {
			continue
		}
		d.After[k] = redactValue(k, av)
	}
	if len(d.Before) == 0 && len(d.After) == 0 {
		return nil
	}
	return d
}

// Created records a new object, with no before.
func Created(v any) *Diff {
	m := toMap(v)
	if m == nil {
		return nil
	}
	after := make(map[string]any, len(m))
	for k, val := range m {
		after[k] = redactValue(k, val)
	}
	return &Diff{After: after}
}

// Deleted records a removed object, with no after.
func Deleted(v any) *Diff {
	m := toMap(v)
	if m == nil {
		return nil
	}
	before := make(map[string]any, len(m))
	for k, val := range m {
		before[k] = redactValue(k, val)
	}
	return &Diff{Before: before}
}

func toMap(v any) map[string]any {
	if v == nil {
		return nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil
	}
	return m
}

// redactValue replaces a secret with a digest of it: two different values
// give two different digests, so a reader can tell a rotation happened
// without learning either one.
func redactValue(key string, v any) any {
	if !looksSecret(key) || v == nil {
		return v
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "<redacted>"
	}
	sum := sha256.Sum256(b)
	return fmt.Sprintf("<redacted:%s>", hex.EncodeToString(sum[:4]))
}
