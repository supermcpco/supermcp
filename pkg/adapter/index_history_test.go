package adapter

import (
	"reflect"
	"testing"
)

func TestCarryHistory(t *testing.T) {
	t.Parallel()
	prev := &Index{Adapters: []IndexEntry{
		{Slug: "changed", ContentHash: "b", PreviousHashes: []string{"a"}},
		{Slug: "same", ContentHash: "s"},
		{Slug: "reverted", ContentHash: "y", PreviousHashes: []string{"x"}},
		{Slug: "retired", ContentHash: "r"},
	}}
	next := &Index{Adapters: []IndexEntry{
		{Slug: "changed", ContentHash: "c"},
		{Slug: "same", ContentHash: "s"},
		{Slug: "reverted", ContentHash: "x"},
		{Slug: "new", ContentHash: "n"},
	}}
	CarryHistory(prev, next)
	want := map[string][]string{"changed": {"a", "b"}, "same": nil, "reverted": {"y"}, "new": nil}
	for _, e := range next.Adapters {
		if !reflect.DeepEqual(e.PreviousHashes, want[e.Slug]) {
			t.Errorf("%s: history %v, want %v", e.Slug, e.PreviousHashes, want[e.Slug])
		}
	}
	changed := next.Adapters[0]
	for hash, behind := range map[string]bool{"a": true, "b": true, "c": false, "unknown": false, "": false} {
		if got := changed.Precedes(hash); got != behind {
			t.Errorf("Precedes(%q) = %v, want %v", hash, got, behind)
		}
	}
}
