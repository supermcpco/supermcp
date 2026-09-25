package invalidation

import (
	"slices"
	"sync"
	"testing"
)

// recordingCache remembers what it was told to drop.
type recordingCache struct {
	mu    sync.Mutex
	calls []string
}

func (c *recordingCache) InvalidateOrg(orgID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = append(c.calls, "org:"+orgID)
}

func (c *recordingCache) InvalidateAll() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = append(c.calls, "all")
}

func (c *recordingCache) got() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.calls)
}

// countingObserver counts invalidations by "cache/source".
type countingObserver struct {
	mu        sync.Mutex
	counts    map[string]int
	connected bool
}

func (o *countingObserver) ObserveCacheInvalidation(cache, source string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.counts == nil {
		o.counts = map[string]int{}
	}
	o.counts[cache+"/"+source]++
}

func (o *countingObserver) SetCacheListenerConnected(connected bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.connected = connected
}

func TestDispatch(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		payload   string
		nonce     string
		wantProbe bool
		wantAuthz []string
		wantDLP   []string
		wantCount map[string]int
	}{
		{name: "one organisation's bindings", payload: "authz:org_1",
			wantAuthz: []string{"org:org_1"}, wantCount: map[string]int{"authz/notify": 1}},
		{name: "one organisation's policies", payload: "dlp:org_1",
			wantDLP: []string{"org:org_1"}, wantCount: map[string]int{"dlp/notify": 1}},
		{name: "a built-in role, which every organisation shares", payload: "authz:*",
			wantAuthz: []string{"all"}, wantCount: map[string]int{"authz/notify": 1}},
		{name: "a kind this build does not know flushes everything", payload: "approvals:org_1",
			wantAuthz: []string{"all"}, wantDLP: []string{"all"},
			wantCount: map[string]int{"authz/notify": 1, "dlp/notify": 1}},
		{name: "a payload that cannot be read flushes everything", payload: "garbage",
			wantAuthz: []string{"all"}, wantDLP: []string{"all"},
			wantCount: map[string]int{"authz/notify": 1, "dlp/notify": 1}},
		{name: "another replica's probe is ignored", payload: "probe:abc", nonce: "",
			wantCount: map[string]int{}},
		{name: "our own probe is recognised", payload: "probe:abc", nonce: "abc", wantProbe: true,
			wantCount: map[string]int{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			obs := &countingObserver{counts: map[string]int{}}
			l := NewListener(Options{Observer: obs})
			az, pol := &recordingCache{}, &recordingCache{}
			l.Register(KindAuthz, az)
			l.Register(KindDLP, pol)

			if got := l.dispatch(tc.payload, tc.nonce); got != tc.wantProbe {
				t.Errorf("probe = %v, want %v", got, tc.wantProbe)
			}
			if got := az.got(); !slices.Equal(got, tc.wantAuthz) {
				t.Errorf("authz calls = %v, want %v", got, tc.wantAuthz)
			}
			if got := pol.got(); !slices.Equal(got, tc.wantDLP) {
				t.Errorf("dlp calls = %v, want %v", got, tc.wantDLP)
			}
			obs.mu.Lock()
			defer obs.mu.Unlock()
			if len(obs.counts) != len(tc.wantCount) {
				t.Errorf("counts = %v, want %v", obs.counts, tc.wantCount)
			}
			for k, v := range tc.wantCount {
				if obs.counts[k] != v {
					t.Errorf("counts[%s] = %d, want %d", k, obs.counts[k], v)
				}
			}
		})
	}
}

func TestDispatchIgnoresAKnownKindNobodyRegistered(t *testing.T) {
	t.Parallel()
	l := NewListener(Options{})
	az := &recordingCache{}
	l.Register(KindAuthz, az)
	l.dispatch("dlp:org_1", "")
	if got := az.got(); len(got) != 0 {
		t.Errorf("a dlp notification reached the authz cache: %v", got)
	}
}

func TestPayloadRoundTrips(t *testing.T) {
	t.Parallel()
	tests := []struct {
		kind    Kind
		org     string
		want    string
		wantAll bool
	}{
		{kind: KindAuthz, org: "org_1", want: "authz:org_1"},
		{kind: KindDLP, org: "", want: "dlp:*", wantAll: true},
	}
	for _, tc := range tests {
		got := Payload(tc.kind, tc.org)
		if got != tc.want {
			t.Errorf("Payload(%s, %q) = %q, want %q", tc.kind, tc.org, got, tc.want)
		}
		m := parse(got)
		if m.kind != tc.kind || m.all != tc.wantAll || (!m.all && m.orgID != tc.org) {
			t.Errorf("parse(%q) = %+v", got, m)
		}
	}
}
