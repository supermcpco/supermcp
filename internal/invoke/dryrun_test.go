package invoke

import (
	"testing"
)

// The control arguments steer this system, not the tool. A preview that
// showed _dry_run as a query parameter would be describing a request
// nobody would ever send.
func TestControlArgumentsAreNotPartOfTheRequest(t *testing.T) {
	in := map[string]any{"_dry_run": true, "_approval": "req_1", "page": 2}
	out := stripControlArgs(in)
	if _, ok := out["_dry_run"]; ok {
		t.Error("the dry-run flag reached the request")
	}
	if _, ok := out["_approval"]; ok {
		t.Error("the approval identifier reached the request")
	}
	if out["page"] != 2 {
		t.Errorf("a real argument was dropped: %v", out)
	}
	if _, ok := in["_dry_run"]; !ok {
		t.Error("the caller's own map was modified")
	}
}

func TestWantsDryRun(t *testing.T) {
	for name, tc := range map[string]struct {
		args map[string]any
		want bool
	}{
		"asked":        {map[string]any{"_dry_run": true}, true},
		"said no":      {map[string]any{"_dry_run": false}, false},
		"absent":       {map[string]any{"page": 1}, false},
		"not a bool":   {map[string]any{"_dry_run": "yes"}, false},
		"no arguments": {nil, false},
	} {
		if got := WantsDryRun(tc.args); got != tc.want {
			t.Errorf("%s: WantsDryRun = %v, wanted %v", name, got, tc.want)
		}
	}
}

// A transport that answers is a dry run that reached the network.
func TestTheDryRunTransportRefuses(t *testing.T) {
	if _, err := (refusingDoer{}).Do(nil); err == nil {
		t.Fatal("the dry-run transport answered a request")
	}
}
