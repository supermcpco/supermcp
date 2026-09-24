package parser

import (
	"reflect"
	"strings"
	"testing"

	"github.com/supermcpco/supermcp/pkg/adapter"
)

// The commands below are the shapes vendor documentation actually prints:
// Stripe's form-encoded POST with the key as the basic-auth username,
// Slack's JSON POST with the token in an environment variable, GitHub's
// path with {owner} and {repo} left blank, OpenAI's JSON body behind a
// pipe into jq.
func TestFromCurl(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		command string
		file    string
		check   func(t *testing.T, a *adapter.Adapter, findings []ImportFinding)
	}{
		{
			name: "stripe, multi-line with a key in -u",
			file: "stripe-charge.curl.txt",
			check: func(t *testing.T, a *adapter.Adapter, findings []ImportFinding) {
				if a.Transport.BaseURL != "https://api.stripe.com" || a.Metadata.Slug != "stripe" {
					t.Errorf("transport = %+v, slug = %q", a.Transport, a.Metadata.Slug)
				}
				if a.Auth.Type != adapter.AuthBasic || a.Auth.Username != "{{env.API_USERNAME}}" {
					t.Errorf("auth = %+v", a.Auth)
				}
				if body := marshal(t, a); strings.Contains(body, "sk_test_") {
					t.Fatal("the pasted key was written into the adapter")
				}
				if !hasFinding(findings, Review, "credential in plain text") {
					t.Errorf("moving the key out should be reported: %v", findings)
				}
				tool := a.Tools[0]
				if tool.Name != "stripe_post_v1_payment_intents" || tool.Operation.Method != "POST" {
					t.Errorf("tool = %q %s", tool.Name, tool.Operation.Method)
				}
				// -d and --data-urlencode together are a form.
				if tool.Operation.Body.Encoding != "form" {
					t.Errorf("encoding = %q", tool.Operation.Body.Encoding)
				}
				want := map[string]any{
					"amount":                 "{{params.amount}}",
					"currency":               "{{params.currency}}",
					"payment_method_types[]": "{{params.payment_method_types}}",
					"description":            "{{params.description}}",
				}
				if got := nodeMap(t, tool.Operation.Body.Value); !reflect.DeepEqual(got, want) {
					t.Errorf("body = %v, want %v", got, want)
				}
				// The wire name keeps its brackets; the parameter cannot.
				if !hasFinding(findings, Info, `"payment_method_types[]" is taken as "payment_method_types"`) {
					t.Errorf("the rename should be reported: %v", findings)
				}
				props := inputMap(t, &tool)["properties"].(map[string]any)
				if amount := props["amount"].(map[string]any); amount["default"] != "2000" {
					t.Errorf("the command's value should become the default, got %v", amount)
				}
				// A header the command carried is what the API requires, not
				// something a model should be offered.
				if got, _ := tool.Operation.Headers.Get("Stripe-Version"); got != "2024-06-20" {
					t.Errorf("Stripe-Version = %q", got)
				}
			},
		},
		{
			name:    "slack, with the token in the environment",
			command: `curl -X POST 'https://slack.com/api/chat.postMessage' -H 'Content-type: application/json; charset=utf-8' -H "Authorization: Bearer $SLACK_BOT_TOKEN" -d '{"channel":"C0123","text":"Hello there","unfurl_links":false}'`,
			check: func(t *testing.T, a *adapter.Adapter, findings []ImportFinding) {
				// $NAME is not execution; it names a value the person keeps
				// in their environment, which is what a credential is.
				if a.Auth.Type != adapter.AuthBearer || a.Auth.Token != "{{env.SLACK_BOT_TOKEN}}" {
					t.Errorf("auth = %+v", a.Auth)
				}
				if cred, ok := a.Credentials.Get("SLACK_BOT_TOKEN"); !ok || !cred.Secret {
					t.Errorf("credential = %+v, ok = %v", cred, ok)
				}
				tool := a.Tools[0]
				if tool.Operation.Body.Encoding != "json" {
					t.Errorf("encoding = %q", tool.Operation.Body.Encoding)
				}
				want := map[string]any{
					"channel":      "{{params.channel}}",
					"text":         "{{params.text}}",
					"unfurl_links": "{{params.unfurl_links}}",
				}
				if got := nodeMap(t, tool.Operation.Body.Value); !reflect.DeepEqual(got, want) {
					t.Errorf("body = %v, want %v", got, want)
				}
				props := inputMap(t, &tool)["properties"].(map[string]any)
				if unfurl := props["unfurl_links"].(map[string]any); unfurl["type"] != "boolean" || unfurl["default"] != false {
					t.Errorf("the example's type should survive, got %v", unfurl)
				}
				// A quoted semicolon is part of the header, not a new command.
				if got, _ := tool.Operation.Headers.Get("Content-type"); got != "application/json; charset=utf-8" {
					t.Errorf("Content-type = %q", got)
				}
				if HasBlockers(findings) {
					t.Errorf("unexpected blockers: %v", findings)
				}
			},
		},
		{
			name:    "github, with blanks left in the path",
			command: `curl -L -H "Accept: application/vnd.github+json" -H "Authorization: Bearer ghp_EXAMPLE_NOT_A_REAL_TOKEN4a" 'https://api.github.com/repos/{owner}/{repo}/issues?state=open&per_page=30'`,
			check: func(t *testing.T, a *adapter.Adapter, findings []ImportFinding) {
				tool := a.Tools[0]
				if tool.Name != "github_get_repos_by_owner_by_repo_issues" {
					t.Errorf("name = %q", tool.Name)
				}
				if tool.Operation.Path != "/repos/{{params.owner}}/{{params.repo}}/issues" {
					t.Errorf("path = %q; the braces documentation writes are parameters, not escaping", tool.Operation.Path)
				}
				required := strs(inputMap(t, &tool)["required"].([]any))
				if !equal(required, []string{"owner", "repo"}) {
					t.Errorf("required = %v", required)
				}
				want := map[string]any{"state": "{{params.state}}", "per_page": "{{params.per_page}}"}
				if got := nodeMap(t, tool.Operation.Query); !reflect.DeepEqual(got, want) {
					t.Errorf("query = %v, want %v", got, want)
				}
				if a.Auth.Token != "{{env.API_TOKEN}}" {
					t.Errorf("auth = %+v", a.Auth)
				}
				if body := marshal(t, a); strings.Contains(body, "ghp_16C7") {
					t.Fatal("the pasted token was written into the adapter")
				}
				if tool.Annotations == nil || tool.Annotations.ReadOnlyHint == nil || !*tool.Annotations.ReadOnlyHint {
					t.Errorf("a GET should read only, got %+v", tool.Annotations)
				}
			},
		},
		{
			name:    "openai, piped into jq",
			command: `curl "https://api.openai.com/v1/responses" -H "Content-Type: application/json" -H "Authorization: Bearer $OPENAI_API_KEY" -d '{"model": "gpt-4.1", "input": "Tell me a story"}' | jq -r '.output_text'`,
			check: func(t *testing.T, a *adapter.Adapter, findings []ImportFinding) {
				if len(a.Tools) != 1 || a.Tools[0].Operation.Path != "/v1/responses" {
					t.Fatalf("tools = %v", toolNames(a))
				}
				if !hasFinding(findings, Info, "the command continues with") {
					t.Errorf("the pipeline should be reported as ignored: %v", findings)
				}
				if a.Auth.Token != "{{env.OPENAI_API_KEY}}" {
					t.Errorf("auth = %+v", a.Auth)
				}
			},
		},
		{
			name:    "a basic auth header is decoded rather than copied",
			command: `curl https://api.example.com/v2/accounts -H 'Authorization: Basic YWRhOmxvdmVsYWNl'`,
			check: func(t *testing.T, a *adapter.Adapter, findings []ImportFinding) {
				if a.Auth.Type != adapter.AuthBasic || a.Auth.Username != "{{env.API_USERNAME}}" || a.Auth.Password != "{{env.API_PASSWORD}}" {
					t.Errorf("auth = %+v", a.Auth)
				}
				if body := marshal(t, a); strings.Contains(body, "YWRhOmxvdmVsYWNl") || strings.Contains(body, "lovelace") {
					t.Fatal("the encoded credentials were written into the adapter")
				}
			},
		},
		{
			name:    "an api key header becomes the connector's auth",
			command: `curl https://api.example.com/v1/ping -H "X-Api-Key: 4d8f3b2a9c7e1f6058d4b3a2c1e9f8d7"`,
			check: func(t *testing.T, a *adapter.Adapter, findings []ImportFinding) {
				if a.Auth.Type != adapter.AuthAPIKey || a.Auth.In != "header" || a.Auth.Name != "X-Api-Key" || a.Auth.Value != "{{env.X_API_KEY}}" {
					t.Errorf("auth = %+v", a.Auth)
				}
			},
		},
		{
			name:    "-G moves the data into the query",
			command: `curl -G https://api.example.com/search --data-urlencode "q=umbrella stand" -d "limit=5"`,
			check: func(t *testing.T, a *adapter.Adapter, findings []ImportFinding) {
				tool := a.Tools[0]
				if tool.Operation.Method != "GET" || tool.Operation.Body != nil {
					t.Errorf("operation = %+v", tool.Operation)
				}
				want := map[string]any{"q": "{{params.q}}", "limit": "{{params.limit}}"}
				if got := nodeMap(t, tool.Operation.Query); !reflect.DeepEqual(got, want) {
					t.Errorf("query = %v, want %v", got, want)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			command := []byte(tc.command)
			if tc.file != "" {
				command = fixture(t, tc.file)
			}
			a, findings, err := FromCurl(command, Options{})
			if err != nil {
				t.Fatalf("FromCurl: %v", err)
			}
			mustValidate(t, a)
			if len(a.Tools) != 1 {
				t.Fatalf("one command is one tool, got %v", toolNames(a))
			}
			tc.check(t, a, findings)
		})
	}
}

// Anything that would need a shell to produce a value is refused. Running
// it is out of the question, and dropping it silently would build a
// request missing a value the person believed they had supplied.
func TestFromCurlRefusesAShell(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		command string
		want    string
	}{
		{
			name:    "command substitution",
			command: `curl https://api.example.com/x -H "Authorization: Bearer $(pass show api/token)"`,
			want:    "$(...) command substitution",
		},
		{
			name:    "backquotes",
			command: "curl https://api.example.com/x -H \"X-Now: `date`\"",
			want:    "a backquoted command",
		},
		{
			name:    "reading the body from a file",
			command: `curl -X POST https://api.example.com/x -d @payload.json`,
			want:    "there is no filesystem behind a connector",
		},
		{
			name:    "uploading a file",
			command: `curl --upload-file ./report.pdf https://api.example.com/x`,
			want:    "there is no filesystem behind a connector",
		},
		{
			name:    "a form part read from disk",
			command: `curl -F "file=@receipt.pdf" https://api.example.com/x`,
			want:    "there is no filesystem behind a connector",
		},
		{
			name:    "the body redirected in",
			command: `curl -X POST https://api.example.com/x -d @- < payload.json`,
			want:    "reads its body from the shell",
		},
		{
			name:    "no URL at all",
			command: `curl -X POST -H "Accept: application/json"`,
			want:    "names no URL",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			a, findings, err := FromCurl([]byte(tc.command), Options{})
			if err == nil {
				t.Fatalf("expected a refusal, got %v", a)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want something about %q", err, tc.want)
			}
			// The reason has to reach the preview as a finding too, or a
			// caller sees a refusal with nothing to act on.
			if !HasBlockers(findings) {
				t.Errorf("a refusal should also be a blocker finding, got %v", findings)
			}
		})
	}
}

func TestFromCurlTokenize(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want []string
	}{
		{name: "quotes join into one word", in: `curl -H'Accept: */*' url`, want: []string{"curl", "-HAccept: */*", "url"}},
		{name: "escaped quote inside quotes", in: `curl -d "{\"a\":1}"`, want: []string{"curl", `-d`, `{"a":1}`}},
		{name: "single quotes keep backslashes", in: `curl -d '{"a":"b\c"}'`, want: []string{"curl", "-d", `{"a":"b\c"}`}},
		{name: "an empty argument survives", in: `curl -u "key:" url`, want: []string{"curl", "-u", "key:", "url"}},
		{name: "a dollar with no name is literal", in: `curl -d 'cost=$5'`, want: []string{"curl", "-d", "cost=$5"}},
		{name: "a shell variable becomes a placeholder", in: `curl -H "X: ${MY_TOKEN}"`, want: []string{"curl", "-H", "X: {{env.MY_TOKEN}}"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, _, err := curlTokenize(tc.in)
			if err != nil {
				t.Fatalf("curlTokenize: %v", err)
			}
			if !equal(got, tc.want) {
				t.Errorf("tokens = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestFromCurlReadsOneCommand(t *testing.T) {
	t.Parallel()

	command := "curl https://api.example.com/a\ncurl https://api.example.com/b\n"
	a, findings, err := FromCurl([]byte(command), Options{})
	if err != nil {
		t.Fatalf("FromCurl: %v", err)
	}
	if len(a.Tools) != 1 || a.Tools[0].Operation.Path != "/a" {
		t.Errorf("tools = %v", toolNames(a))
	}
	if !hasFinding(findings, Blocker, "more than one curl command") {
		t.Errorf("the second command should be a blocker: %v", findings)
	}
}
