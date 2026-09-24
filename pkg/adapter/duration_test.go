package adapter_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/supermcpco/supermcp/pkg/adapter"
)

// A tool definition is stored as JSON and read back on every call, so a
// duration that cannot survive that trip takes the connector down. It did:
// the writing side quoted the duration and nothing could read it.
func TestDurationSurvivesJSON(t *testing.T) {
	for _, want := range []string{"30s", "5m", "1h30m", "24h"} {
		d, err := time.ParseDuration(want)
		if err != nil {
			t.Fatal(err)
		}
		b, err := json.Marshal(adapter.Duration(d))
		if err != nil {
			t.Fatalf("marshalling %s: %v", want, err)
		}
		if string(b) != `"`+want+`"` {
			t.Errorf("%s marshalled as %s, expected a quoted duration", want, b)
		}
		var got adapter.Duration
		if err := json.Unmarshal(b, &got); err != nil {
			t.Fatalf("reading %s back: %v", want, err)
		}
		if time.Duration(got) != d {
			t.Errorf("%s read back as %s", want, got)
		}
	}
	// A definition written as a bare number still reads, so an existing row
	// does not take its connector down.
	var legacy adapter.Duration
	if err := json.Unmarshal([]byte("86400000000000"), &legacy); err != nil || time.Duration(legacy) != 24*time.Hour {
		t.Errorf("a numeric duration no longer reads: %v %s", err, legacy)
	}
}
