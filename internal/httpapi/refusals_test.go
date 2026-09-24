package httpapi

import (
	"testing"
	"time"
)

func TestRefusalsAreRecordedUpToABudgetThenCounted(t *testing.T) {
	now := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	b := newRefusalBudget(func() time.Time { return now })

	for i := 0; i < refusalsPerWindow; i++ {
		if suppressed, record := b.admit("client-a"); !record || suppressed != 0 {
			t.Fatalf("refusal %d: record=%v suppressed=%d, want recorded with nothing suppressed", i+1, record, suppressed)
		}
	}
	for i := 0; i < 25; i++ {
		if _, record := b.admit("client-a"); record {
			t.Fatalf("refusal %d past the budget was recorded", refusalsPerWindow+i+1)
		}
	}
	// Another client has its own budget.
	if _, record := b.admit("client-b"); !record {
		t.Fatal("a second client was counted against the first one's budget")
	}

	// The next refusal after the window reports what was suppressed, once.
	now = now.Add(refusalWindow)
	suppressed, record := b.admit("client-a")
	if !record || suppressed != 25 {
		t.Fatalf("after the window: record=%v suppressed=%d, want recorded with 25 suppressed", record, suppressed)
	}
	if suppressed, _ := b.admit("client-a"); suppressed != 0 {
		t.Fatalf("the suppressed count was reported twice: %d", suppressed)
	}

	// A nil budget records everything, so a Deps built by hand in a test
	// still audits.
	var none *refusalBudget
	if _, record := none.admit("x"); !record {
		t.Fatal("a nil budget suppressed a refusal")
	}
}
