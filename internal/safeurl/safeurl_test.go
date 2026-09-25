package safeurl

import "testing"

func TestDisplay(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, in, want string
	}{
		{name: "plain", in: "https://siem.example.com/ingest", want: "https://siem.example.com/ingest"},
		{name: "query api key", in: "https://api.example.com/v1/items?limit=5&api_key=sk_live_abc", want: "https://api.example.com/v1/items?***"},
		{name: "user info", in: "https://bob:hunter2@hooks.example.com/x", want: "https://hooks.example.com/x"},
		{name: "fragment", in: "https://a.example/x#token=abc", want: "https://a.example/x"},
		{name: "port kept", in: "http://10.0.0.5:8080/hook", want: "http://10.0.0.5:8080/hook"},
		{name: "slack webhook", in: "https://hooks.slack.com/services/T0AAAAAAA/B0BBBBBBB/xoxAbCdEfGhIjKlMnOpQrStUv", want: "https://hooks.slack.com/services/T0AAAAAAA/B0BBBBBBB/***"}, // gitleaks:allow
		{name: "telegram bot", in: "https://api.telegram.org/bot123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw/sendMessage", want: "https://api.telegram.org/***/sendMessage"},
		{name: "a long slug is kept", in: "https://a.example/connector-created-events-archive", want: "https://a.example/connector-created-events-archive"},
		{name: "not a url", in: "::nope", want: ""},
		{name: "no host", in: "/relative/path?key=1", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := Display(tt.in); got != tt.want {
				t.Errorf("Display(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
