package adapter

import (
	"encoding/json"
	"testing"
	"time"
)

func TestDurationString(t *testing.T) {
	cases := map[time.Duration]string{
		0: "0s", 30 * time.Second: "30s", 5 * time.Minute: "5m", 30 * time.Minute: "30m",
		90 * time.Second: "1m30s", time.Hour: "1h", 720 * time.Hour: "720h", 90 * time.Minute: "1h30m",
		3*time.Hour + 5*time.Second: "3h0m5s",
	}
	for in, want := range cases {
		if got := Duration(in).String(); got != want {
			t.Errorf("Duration(%v).String() = %q, want %q", in, got, want)
		}
		var d Duration
		if err := d.UnmarshalYAML(scalar(want)); err != nil || d != Duration(in) {
			t.Errorf("round trip %q: got %v err %v", want, time.Duration(d), err)
		}
	}
}

// TestJSONRoundTrip covers the path a connector takes through JSONB:
// marshal, store, read back. Ordered maps and free-form nodes must survive.
func TestJSONRoundTrip(t *testing.T) {
	in := Auth{
		Type:         AuthHMAC,
		Secret:       "{{env.SECRET}}",
		ExtraHeaders: OrderedMap[string]{Keys: []string{"B", "A"}, Values: map[string]string{"B": "2", "A": "1"}},
		Params:       OrderedMap[string]{Keys: []string{"k"}, Values: map[string]string{"k": "v"}},
	}
	body, err := NodeFromJSON([]byte(`{"user":"{{auth.username}}","n":2,"nested":{"x":[1,2]}}`))
	if err != nil {
		t.Fatal(err)
	}
	in.Request = &LoginRequest{Method: "POST", URL: "https://x", Body: body}

	raw, err := jsonMarshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out Auth
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if got := out.ExtraHeaders.Keys; len(got) != 2 || got[0] != "B" || got[1] != "A" {
		t.Errorf("extraHeaders order lost: %v", got)
	}
	if out.ExtraHeaders.Values["A"] != "1" || out.Params.Values["k"] != "v" {
		t.Errorf("map values lost: %+v %+v", out.ExtraHeaders, out.Params)
	}
	if out.Request == nil || out.Request.Body == nil || out.Request.Body.N == nil {
		t.Fatal("login body lost")
	}
	v, err := out.Request.Body.Value()
	if err != nil {
		t.Fatal(err)
	}
	m := v.(map[string]any)
	if m["user"] != "{{auth.username}}" {
		t.Errorf("body content lost: %#v", m)
	}
}
