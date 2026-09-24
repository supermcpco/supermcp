package parser

import (
	"strings"
	"testing"
)

func TestDetect(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		doc  string
		file string
		want Format
		// why is a fragment of the explanation an undetectable document
		// has to come back with.
		why string
	}{
		{name: "an openapi document", file: "petstore-3.0.json", want: FormatOpenAPI},
		{name: "a postman collection", file: "acme-billing.postman_collection.json", want: FormatPostman},
		{name: "an introspection response", file: "shop-introspection.json", want: FormatGraphQL},
		{name: "a curl command", file: "stripe-charge.curl.txt", want: FormatCurl},
		{name: "a curl command with the prompt still on it", doc: "$ curl https://api.example.com/x", want: FormatCurl},
		{name: "openapi as yaml", doc: "openapi: 3.1.0\ninfo:\n  title: Thing\n", want: FormatOpenAPI},
		{name: "a bare __schema", doc: `{"__schema":{"queryType":{"name":"Query"},"types":[]}}`, want: FormatGraphQL},
		{name: "an unwrapped schema", doc: `{"queryType":{"name":"Query"},"types":[]}`, want: FormatGraphQL},

		{name: "nothing at all", doc: "   ", want: FormatUnknown, why: "nothing to read"},
		{name: "prose", doc: "please import my API, thanks", want: FormatUnknown, why: "is not an object"},
		{name: "a JSON object that is none of them", doc: `{"name":"thing","endpoints":[]}`, want: FormatUnknown, why: "none of the marks"},
		{name: "a JSON array", doc: `[{"url":"https://example.com"}]`, want: FormatUnknown, why: "not an object"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			doc := []byte(tc.doc)
			if tc.file != "" {
				doc = fixture(t, tc.file)
			}
			got, why := Detect(doc)
			if got != tc.want {
				t.Fatalf("Detect = %q (%s), want %q", got, why, tc.want)
			}
			if tc.want == FormatUnknown {
				if !strings.Contains(why, tc.why) {
					t.Errorf("why = %q, want something about %q", why, tc.why)
				}
				return
			}
			if why != "" {
				t.Errorf("a detected format should carry no doubt, got %q", why)
			}
		})
	}
}

// A document that reads as two formats is a question, not a coin toss:
// this one carries both an OpenAPI version and a collection's shape.
func TestDetectSaysWhenItCannotTell(t *testing.T) {
	t.Parallel()

	doc := `{"openapi":"3.0.0","info":{"name":"Both"},"item":[]}`
	got, why := Detect([]byte(doc))
	if got != FormatUnknown {
		t.Fatalf("Detect = %q, want it to refuse", got)
	}
	if !strings.Contains(why, "openapi") || !strings.Contains(why, "postman") {
		t.Errorf("why = %q; it should name both readings", why)
	}
}

func TestParseFormat(t *testing.T) {
	t.Parallel()

	for _, f := range Formats {
		got, ok := ParseFormat(string(f))
		if !ok || got != f {
			t.Errorf("ParseFormat(%q) = %q, %v", f, got, ok)
		}
	}
	if _, ok := ParseFormat("wsdl"); ok {
		t.Error("ParseFormat accepted a format this package cannot import")
	}
	if _, ok := ParseFormat("auto"); ok {
		t.Error(`ParseFormat accepted "auto"; choosing is the caller's job, not this function's`)
	}
}

func TestLooksSecret(t *testing.T) {
	t.Parallel()

	names := map[string]bool{
		"X-Api-Key": true, "api_key": true, "apiKey": true, "Authorization": true,
		"clientSecret": true, "password": true, "session_id": true,
		"author": false, "Accept": false, "X-Request-Id": false, "limit": false,
	}
	for name, want := range names {
		if got := looksSecretName(name); got != want {
			t.Errorf("looksSecretName(%q) = %v, want %v", name, got, want)
		}
	}

	values := map[string]bool{
		"sk_live_EXAMPLE_NOT_A_REAL_KEY":   true,
		"ghp_EXAMPLE_NOT_A_REAL_TOKEN":     true,
		"eyJhbGciOiJIUzI1NiJ9.e30.abc":     true,
		"4d8f3b2a9c7e1f6058d4b3a2c1e9f8d7": true,
		"application/json":                 false,
		"2024-06-20":                       false,
		"gbp":                              false,
		"":                                 false,
	}
	for value, want := range values {
		if got := looksSecretValue(value); got != want {
			t.Errorf("looksSecretValue(%q) = %v, want %v", value, got, want)
		}
	}
}

func TestHostName(t *testing.T) {
	t.Parallel()

	hosts := map[string]string{
		"api.stripe.com":      "stripe",
		"api.github.com":      "github",
		"slack.com":           "slack",
		"shop.example.co.uk":  "example",
		"graphql.example.com": "example",
		"localhost:8080":      "localhost",
	}
	for host, want := range hosts {
		if got := hostName(host); got != want {
			t.Errorf("hostName(%q) = %q, want %q", host, got, want)
		}
	}
}
