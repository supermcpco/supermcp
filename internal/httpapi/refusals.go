package httpapi

import (
	"sync"
	"time"
)

// A refused token request is worth recording: a wrong secret or a
// replayed code is how a stolen credential shows itself. It is also
// something a client can produce as fast as it can send requests, and
// the rate limiter that would slow it down is optional. So refusals are
// recorded in full up to a budget per client and minute, and past it
// they are counted and reported as one event when the minute is up,
// which keeps the trail readable and the database out of the blast
// radius without losing the fact that it happened.

const (
	refusalsPerWindow = 10
	refusalWindow     = time.Minute
)

// refusalBudget counts refused token requests per client.
type refusalBudget struct {
	mu      sync.Mutex
	clients map[string]*refusalWindowState
	now     func() time.Time
}

type refusalWindowState struct {
	start      time.Time
	recorded   int
	suppressed int
}

func newRefusalBudget(now func() time.Time) *refusalBudget {
	if now == nil {
		now = time.Now
	}
	return &refusalBudget{clients: map[string]*refusalWindowState{}, now: now}
}

// admit decides whether this refusal is recorded on its own. It returns
// how many refusals were suppressed in the client's previous window, so
// the caller can report them once, and true when this one should be
// recorded.
func (b *refusalBudget) admit(clientID string) (suppressed int, record bool) {
	if b == nil {
		return 0, true
	}
	now := b.now()
	b.mu.Lock()
	defer b.mu.Unlock()
	w := b.clients[clientID]
	if w == nil || now.Sub(w.start) >= refusalWindow {
		if len(b.clients) >= 10000 {
			for id, old := range b.clients {
				if now.Sub(old.start) >= refusalWindow {
					delete(b.clients, id)
				}
			}
		}
		if w != nil {
			suppressed = w.suppressed
		}
		w = &refusalWindowState{start: now}
		b.clients[clientID] = w
	}
	if w.recorded < refusalsPerWindow {
		w.recorded++
		return suppressed, true
	}
	w.suppressed++
	return suppressed, false
}
