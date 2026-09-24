package invoke

import (
	"net/url"
	"reflect"
	"testing"

	"github.com/supermcpco/supermcp/internal/engine"
)

// A preview is shown to anybody who may call the tool, and a credential
// placeholder can render anywhere in the request, not only in a header
// whose name looks secret. Every rendered form of a credential has to go.
func TestScrubEnvRedactsEveryRenderedForm(t *testing.T) {
	t.Parallel()
	const key = "s3cr3t key/with&odd=chars"
	env := map[string]string{
		"API_KEY": key,
		"SHORT":   "abc",       // below the length floor: left alone
		"PREFIX":  "s3cr3t",    // contained in API_KEY: API_KEY must win
		"HTMLISH": "<tok&en>!", // JSON escapes differ with and without HTML escaping
	}
	auth := map[string]string{"access_token": "ya29.stored-token"}

	tests := []struct {
		name string
		in   engine.Preview
		want engine.Preview
	}{
		{
			name: "query-escaped in the URL",
			in:   engine.Preview{URL: "https://api.example.com/v1/items?key=" + url.QueryEscape(key) + "&abc=1"},
			want: engine.Preview{URL: "https://api.example.com/v1/items?key=<redacted:env.API_KEY>&abc=1"},
		},
		{
			name: "path-escaped in the URL",
			in:   engine.Preview{URL: "https://api.example.com/" + url.PathEscape(key) + "/items"},
			want: engine.Preview{URL: "https://api.example.com/<redacted:env.API_KEY>/items"},
		},
		{
			name: "raw in a header whose name looks harmless",
			in:   engine.Preview{Headers: map[string]string{"X-Tenant": key, "Accept": "application/json"}},
			want: engine.Preview{Headers: map[string]string{"X-Tenant": "<redacted:env.API_KEY>", "Accept": "application/json"}},
		},
		{
			name: "JSON-escaped in the body, HTML-escaped and not",
			in:   engine.Preview{Body: `{"a":"<tok&en>!","b":"<tok&en>!","k":"s3cr3t key/with&odd=chars"}`},
			want: engine.Preview{Body: `{"a":"<redacted:env.HTMLISH>","b":"<redacted:env.HTMLISH>","k":"<redacted:env.API_KEY>"}`},
		},
		{
			name: "the shorter secret alone is still redacted",
			in:   engine.Preview{Body: "prefix s3cr3t only"},
			want: engine.Preview{Body: "prefix <redacted:env.PREFIX> only"},
		},
		{
			name: "SQL and string arguments; other arguments untouched",
			in:   engine.Preview{SQL: "SELECT * FROM t WHERE k = 's3cr3t'", Args: []any{key, 42, "abc", "ya29.stored-token"}},
			want: engine.Preview{SQL: "SELECT * FROM t WHERE k = '<redacted:env.PREFIX>'", Args: []any{"<redacted:env.API_KEY>", 42, "abc", "<redacted:auth.access_token>"}},
		},
		{
			name: "a value below the floor is not scrubbed",
			in:   engine.Preview{URL: "https://abc.example.com/"},
			want: engine.Preview{URL: "https://abc.example.com/"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := tc.in
			if tc.in.Headers != nil {
				got.Headers = make(map[string]string, len(tc.in.Headers))
				for k, v := range tc.in.Headers {
					got.Headers[k] = v
				}
			}
			if tc.in.Args != nil {
				got.Args = append([]any(nil), tc.in.Args...)
			}
			scrubEnv(&got, env, auth)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("scrubEnv:\n got  %+v\n want %+v", got, tc.want)
			}
		})
	}
}

// Two credentials with the same value redact to one stable label, and
// nothing to scrub leaves the preview as it was.
func TestScrubEnvEdgeCases(t *testing.T) {
	t.Parallel()
	p := &engine.Preview{Body: "same-value"}
	scrubEnv(p, map[string]string{"B": "same-value", "A": "same-value"}, nil)
	if p.Body != "<redacted:env.A>" {
		t.Errorf("shared value redacted as %q, wanted the first name in order", p.Body)
	}

	p = &engine.Preview{URL: "https://x.example/", Body: "b"}
	scrubEnv(p, nil, nil)
	if p.URL != "https://x.example/" || p.Body != "b" {
		t.Errorf("preview changed with nothing to scrub: %+v", p)
	}
	scrubEnv(nil, map[string]string{"A": "abcd"}, nil) // must not panic
}
