package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/supermcpco/supermcp/internal/secrets"
)

// The report is what an operator reads to decide whether a previous key
// can go: a key under the old reference, even one that opens, keeps it.
func TestBuildVerifyReport(t *testing.T) {
	t.Parallel()
	local := func(b byte, ref string) secrets.KEK {
		k, err := secrets.NewLocal(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, 32)), ref)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	active, previous := local(1, "file:/new"), local(2, "file:/old")
	set := &secrets.KEKSet{Active: active, Previous: []secrets.KEK{previous}}
	checks := []secrets.DataKeyCheck{
		{Key: &secrets.DataKey{ID: [16]byte{1}, Scope: "instance", KEKRef: active.Ref(), Status: "active"}, Active: true, HeldBy: secrets.HeldByActive},
		{Key: &secrets.DataKey{ID: [16]byte{2}, Scope: "org:a", KEKRef: previous.Ref(), Status: "active"}, HeldBy: secrets.HeldByPrevious},
		{Key: &secrets.DataKey{ID: [16]byte{3}, Scope: "org:b", KEKRef: "local:file:/gone", Status: "retired"}, Err: errors.New("no key")},
	}
	rep := buildVerifyReport(set, checks)
	if rep.Checked != 3 || rep.UnderActive != 1 || len(rep.Failed) != 1 || len(rep.Keys) != 3 {
		t.Fatalf("report = %+v", rep)
	}
	if rep.Active != active.Ref() || len(rep.Previous) != 1 || rep.Previous[0] != previous.Ref() {
		t.Fatalf("keys named = %s %v", rep.Active, rep.Previous)
	}
	if k := rep.Keys[1]; k.Active || k.HeldBy != "previous" || k.KEKRef != previous.Ref() || k.KeyID != "02000000" {
		t.Fatalf("previous key's line = %+v", k)
	}
	if f := rep.Failed[0]; f.Scope != "org:b" || f.Error != "no key" {
		t.Fatalf("failed = %+v", f)
	}

	// A row that names the active key but does not open under it (a blob
	// swapped in beside the active reference) is not counted as moved.
	spoof := buildVerifyReport(set, []secrets.DataKeyCheck{
		{Key: &secrets.DataKey{ID: [16]byte{4}, Scope: "org:c", KEKRef: active.Ref(), Status: "active"},
			Active: true, HeldBy: secrets.HeldByActive, Err: errors.New("does not open")},
	})
	if spoof.UnderActive != 0 || spoof.Keys[0].Active || spoof.Keys[0].HeldBy != "" || len(spoof.Failed) != 1 {
		t.Fatalf("a key that does not open was reported under the active key: %+v", spoof)
	}
}
