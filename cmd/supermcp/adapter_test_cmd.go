package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/supermcpco/supermcp/internal/cassette"
	"github.com/supermcpco/supermcp/internal/engine"
	"github.com/supermcpco/supermcp/internal/engine/graphql"
	"github.com/supermcpco/supermcp/internal/engine/rest"
	"github.com/supermcpco/supermcp/internal/httpclient"
	"github.com/supermcpco/supermcp/internal/ssrf"
	"github.com/supermcpco/supermcp/internal/transform"
	"github.com/supermcpco/supermcp/internal/upstreamauth"
	"github.com/supermcpco/supermcp/pkg/adapter"
	"github.com/supermcpco/supermcp/pkg/tmpl"
)

// reEnvRef finds the credentials an adapter reads, including any it uses
// without declaring. An undeclared one is still a credential on the wire,
// and a recording that did not know about it would leak it.
var reEnvRef = regexp.MustCompile(`\{\{\s*env\.([A-Za-z_][A-Za-z0-9_]*)`)

func adapterRecord(args []string) error {
	fs := flag.NewFlagSet("adapter record", flag.ContinueOnError)
	root := fs.String("root", "adapters", "adapters root")
	slug := fs.String("adapter", "", "adapter slug (required)")
	tool := fs.String("tool", "", "record one tool (default: every tool whose arguments are known)")
	paramsJSON := fs.String("params", "", "JSON arguments for --tool")
	live := fs.Bool("live", false, "call the real upstream; recording is refused without it")
	timeout := fs.Duration("timeout", 30*time.Second, "per-call timeout")
	maxBody := fs.Int64("max-body", cassette.DefaultMaxBodyBytes, "refuse to record a body larger than this")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *slug == "" {
		return errors.New("--adapter is required")
	}
	if !*live {
		return errors.New("recording calls the real upstream with real credentials; pass --live to say so")
	}
	if *paramsJSON != "" && *tool == "" {
		return errors.New("--params applies to one tool; pass --tool as well")
	}
	var override map[string]any
	if *paramsJSON != "" {
		if err := json.Unmarshal([]byte(*paramsJSON), &override); err != nil {
			return fmt.Errorf("--params is not a JSON object: %w", err)
		}
	}

	f, dir, err := findAdapter(*root, *slug)
	if err != nil {
		return err
	}
	a := f.Adapter
	eng, err := engineFor(a.Transport.Type)
	if err != nil {
		return err
	}
	tools, err := selectTools(a, *tool)
	if err != nil {
		return err
	}

	env := map[string]string{}
	var unset, supplied []string
	// An unset credential stays out of the map rather than going in empty:
	// that is what a connector with nothing configured looks like, and a
	// template resolving to "" would send a header the gateway would drop.
	for _, name := range credentialNames(a) {
		v := os.Getenv(name)
		switch {
		case v != "":
			env[name] = v
			supplied = append(supplied, name)
		case requiredCredential(a, name):
			unset = append(unset, name)
		}
	}
	if len(unset) > 0 {
		return fmt.Errorf("%s needs %s in the environment", *slug, strings.Join(unset, ", "))
	}
	secrets := cassette.NewSecrets(env)
	client := liveClient(a, *timeout)

	recorded, skipped, failed := 0, 0, 0
	for _, t := range tools {
		path := cassette.Path(dir, t.Name)
		sets, err := paramSets(a, t, path, override)
		if err != nil {
			fmt.Printf("  skip  %-40s %v\n", t.Name, err)
			skipped++
			continue
		}
		c := &cassette.Cassette{
			Adapter: a.Metadata.Slug, Tool: t.Name,
			RecordedAt: time.Now().UTC().Truncate(time.Second), Credentials: supplied,
		}
		for _, params := range sets {
			in, err := recordOne(eng, f, t, params, env, secrets, client, *timeout, *maxBody)
			if err != nil {
				fmt.Printf("  fail  %-40s %v\n", t.Name, err)
				failed++
				c = nil
				break
			}
			c.Interactions = append(c.Interactions, in)
		}
		if c == nil {
			continue
		}
		if err := c.Save(path, secrets); err != nil {
			return err
		}
		fmt.Printf("  ok    %-40s %d exchange(s) → %s\n", t.Name, len(c.Interactions), path)
		recorded++
	}
	fmt.Printf("%s: %d recorded, %d skipped, %d failed\n", *slug, recorded, skipped, failed)
	if failed > 0 {
		return fmt.Errorf("%d tool(s) did not record", failed)
	}
	return nil
}

func adapterTest(args []string) error {
	fs := flag.NewFlagSet("adapter test", flag.ContinueOnError)
	root := fs.String("root", "adapters", "adapters root")
	slug := fs.String("adapter", "", "test one adapter (default: every adapter with cassettes)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var files []*adapter.File
	if *slug != "" {
		f, _, err := findAdapter(*root, *slug)
		if err != nil {
			return err
		}
		files = []*adapter.File{f}
	} else {
		all, err := adapter.LoadDir(*root)
		if err != nil {
			err = explainMissingRoot(*root, err)
			return err
		}
		files = all
	}

	adapters, played, failures := 0, 0, 0
	for _, f := range files {
		dir := filepath.Join(*root, filepath.FromSlash(f.Dir))
		cassettes, err := cassette.LoadDir(dir)
		if err != nil {
			return err
		}
		if len(cassettes) == 0 {
			continue
		}
		adapters++
		fmt.Println(f.Adapter.Metadata.Slug)
		for _, c := range cassettes {
			played++
			if err := replay(f, c); err != nil {
				failures++
				fmt.Printf("  fail  %-44s %v\n", c.Tool, err)
				continue
			}
			fmt.Printf("  pass  %-44s %d exchange(s)\n", c.Tool, len(c.Interactions))
		}
	}
	fmt.Printf("%d adapter(s), %d cassette(s), %d failure(s)\n", adapters, played, failures)
	if failures > 0 {
		return fmt.Errorf("%d cassette(s) failed", failures)
	}
	return nil
}

// recordOne runs one call against the upstream and returns the exchange.
// The authenticator gets the live client rather than the recorder: a token
// endpoint's answer is a credential, and nothing that is not the tool's own
// exchange belongs in a cassette.
func recordOne(eng engine.Engine, f *adapter.File, t *adapter.Tool, params map[string]any,
	env map[string]string, secrets *cassette.Secrets, client *httpclient.Client, timeout time.Duration, maxBody int64,
) (cassette.Interaction, error) {
	rec := cassette.NewRecorder(client, secrets, cassette.Options{KeepResponseHeaders: exposedHeaders(t), MaxBodyBytes: maxBody})
	// The timeout covers the token endpoint as well as the call: a
	// credential fetch that hangs is the same wait to whoever is watching.
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := buildRequest(ctx, f, t, params, env, rec, client, false)
	if err != nil {
		return cassette.Interaction{}, err
	}
	resp, err := eng.Execute(ctx, req)
	var upstream *engine.UpstreamError
	switch {
	case errors.As(err, &upstream):
		return cassette.Interaction{}, fmt.Errorf("upstream answered %d: %s", upstream.Status, firstLine(upstream.Body))
	case err != nil:
		return cassette.Interaction{}, err
	}
	if resp.Stream != nil {
		_ = resp.Stream.Close()
		return cassette.Interaction{}, fmt.Errorf("%s responses are binary and are not recorded", resp.MediaType)
	}
	in, ok := rec.Last()
	if !ok {
		return cassette.Interaction{}, errors.New("the engine sent nothing")
	}
	in.Params = params
	return in, nil
}

// replay proves one cassette: every recorded exchange must still be the
// request this build produces, the response must still decode, and a
// response transform must still select something from it.
func replay(f *adapter.File, c *cassette.Cassette) error {
	t := findTool(f.Adapter, c.Tool)
	if t == nil {
		return fmt.Errorf("the adapter no longer has a tool called %s", c.Tool)
	}
	eng, err := engineFor(f.Adapter.Transport.Type)
	if err != nil {
		return err
	}
	// Each credential the recording had is set to its own marker, which is
	// what recording substituted, so a request built here matches without a
	// secret ever existing on this machine.
	env := map[string]string{}
	for _, name := range c.Credentials {
		env[name] = cassette.Marker(name)
	}
	player := cassette.NewPlayer(c)
	for _, in := range c.Interactions {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		req, err := buildRequest(ctx, f, t, in.Params, env, player, offlineDoer{}, true)
		if err != nil {
			cancel()
			return err
		}
		resp, err := eng.Execute(ctx, req)
		cancel()
		if err != nil {
			return err
		}
		if resp.Status != in.Response.Status {
			return fmt.Errorf("replayed status %d, recorded %d", resp.Status, in.Response.Status)
		}
		if resp.Stream != nil {
			_ = resp.Stream.Close()
			continue
		}
		if err := checkTransform(t, resp.Body); err != nil {
			return err
		}
	}
	return nil
}

// checkTransform is the assertion a request-parity harness cannot make:
// the JMESPath still finds what it was written for in the body the
// upstream actually returns.
func checkTransform(t *adapter.Tool, body any) error {
	if t.Response == nil || t.Response.Transform == nil || t.Response.Transform.JMESPath == "" {
		return nil
	}
	out := transform.Apply(&transform.Spec{
		JMESPath:      t.Response.Transform.JMESPath,
		MaxBytes:      t.Response.MaxBytes,
		FallbackToRaw: t.Response.FallbackToRaw,
	}, body)
	if out.Err != nil {
		return fmt.Errorf("response transform %q failed: %w", t.Response.Transform.JMESPath, out.Err)
	}
	if body != nil && out.Value == nil {
		return fmt.Errorf("response transform %q selects nothing from the recorded response", t.Response.Transform.JMESPath)
	}
	return nil
}

// buildRequest assembles the call the engine executes. offline says the
// request will be replayed: auth schemes that would fetch a token are left
// off, because the headers they set are the ones a cassette drops and are
// therefore never matched on.
func buildRequest(ctx context.Context, f *adapter.File, t *adapter.Tool, params map[string]any, env map[string]string,
	doer, authDoer engine.HTTPDoer, offline bool,
) (*engine.Request, error) {
	a := f.Adapter
	conn := &engine.Connector{
		ID:      a.Metadata.Slug,
		Type:    a.Transport.Type,
		BaseURL: a.Transport.BaseURL,
		Headers: a.Transport.Headers,
		Auth:    a.Auth,
	}
	vars := tmpl.Vars{Params: withDefaults(t, params), Env: env}
	var auth engine.Authenticator
	if !offline || staticAuth(a.Auth.Type) {
		prepared, out, err := upstreamauth.Prepare(ctx, conn, vars, upstreamauth.Deps{HTTP: authDoer})
		switch {
		case err != nil && !offline:
			return nil, err
		case err == nil:
			auth, vars = prepared, out
		}
	}
	return &engine.Request{
		Connector: conn,
		Tool:      t,
		Vars:      vars,
		Auth:      auth,
		HTTP:      doer,
		Limits:    engine.Limits{MaxRows: t.Operation.MaxRows, MaxInlineBytes: cassette.DefaultMaxBodyBytes},
	}, nil
}

// staticAuth reports whether a scheme puts a credential on the request
// without asking an upstream for a token first.
func staticAuth(t adapter.AuthType) bool {
	switch t {
	case adapter.AuthNone, "", adapter.AuthAPIKey, adapter.AuthBearer, adapter.AuthBasic, adapter.AuthQuery:
		return true
	}
	return false
}

// offlineDoer is what an authenticator gets during replay. Nothing should
// call it; if something does, the failure names the reason.
type offlineDoer struct{}

func (offlineDoer) Do(*http.Request) (*http.Response, error) {
	return nil, errors.New("replaying a cassette must not reach the network")
}

// paramSets decides what to call the tool with: the operator's arguments,
// else the ones the existing cassette was recorded with (so a refresh
// needs no arguments at all), else the healthcheck's, else nothing when
// the tool needs nothing.
func paramSets(a *adapter.Adapter, t *adapter.Tool, path string, override map[string]any) ([]map[string]any, error) {
	if override != nil {
		return []map[string]any{override}, nil
	}
	if existing, err := cassette.Load(path); err == nil && len(existing.Interactions) > 0 {
		out := make([]map[string]any, 0, len(existing.Interactions))
		for _, in := range existing.Interactions {
			out = append(out, in.Params)
		}
		return out, nil
	}
	if a.Healthcheck != nil && a.Healthcheck.Tool == t.Name && a.Healthcheck.Params != nil {
		v, err := a.Healthcheck.Params.Value()
		if err != nil {
			return nil, err
		}
		if m, ok := v.(map[string]any); ok {
			return []map[string]any{m}, nil
		}
	}
	if missing := requiredParams(t); len(missing) > 0 {
		return nil, fmt.Errorf("needs %s; pass --tool %s --params '{...}'", strings.Join(missing, ", "), t.Name)
	}
	return []map[string]any{{}}, nil
}

// withDefaults fills in schema defaults the way an invocation does, so a
// recording is the call a caller would make and not a barer one.
func withDefaults(t *adapter.Tool, params map[string]any) map[string]any {
	out := make(map[string]any, len(params))
	for k, v := range params {
		out[k] = v
	}
	if t.Input == nil || t.Input.N == nil {
		return out
	}
	props := adapter.MapGet(t.Input.N, "properties")
	for _, name := range adapter.MapKeys(props) {
		if _, ok := out[name]; ok {
			continue
		}
		if d := adapter.MapGet(adapter.MapGet(props, name), "default"); d != nil {
			if v, err := adapter.NodeValue(d); err == nil {
				out[name] = v
			}
		}
	}
	return out
}

// requiredParams lists the arguments a tool needs and cannot default.
func requiredParams(t *adapter.Tool) []string {
	if t.Input == nil || t.Input.N == nil {
		return nil
	}
	req := adapter.MapGet(t.Input.N, "required")
	if req == nil {
		return nil
	}
	v, err := adapter.NodeValue(req)
	if err != nil {
		return nil
	}
	list, ok := v.([]any)
	if !ok {
		return nil
	}
	defaults := withDefaults(t, nil)
	var out []string
	for _, e := range list {
		name, ok := e.(string)
		if !ok {
			continue
		}
		if _, hasDefault := defaults[name]; !hasDefault {
			out = append(out, name)
		}
	}
	return out
}

func credentialNames(a *adapter.Adapter) []string {
	seen := map[string]bool{}
	for _, k := range a.Credentials.Keys {
		seen[k] = true
	}
	if data, err := adapter.Marshal(a); err == nil {
		for _, m := range reEnvRef.FindAllStringSubmatch(string(data), -1) {
			seen[m[1]] = true
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func requiredCredential(a *adapter.Adapter, name string) bool {
	c, ok := a.Credentials.Get(name)
	return ok && c.Required
}

func exposedHeaders(t *adapter.Tool) []string {
	if t.Response == nil {
		return nil
	}
	return t.Response.ExposeHeaders
}

func engineFor(t adapter.TransportType) (engine.Engine, error) {
	switch t {
	case adapter.TransportHTTP:
		return rest.Engine{}, nil
	case adapter.TransportGraphQL:
		return graphql.Engine{}, nil
	}
	return nil, fmt.Errorf("transport %s has no cassettes: only http and graphql exchanges are recorded", t)
}

// liveClient is the production client, so what a cassette records is what
// the gateway would have sent.
func liveClient(a *adapter.Adapter, timeout time.Duration) *httpclient.Client {
	policy := httpclient.DefaultPolicy()
	policy.TotalTimeout = timeout
	if a.Transport.Timeout != 0 && time.Duration(a.Transport.Timeout) < timeout {
		policy.TotalTimeout = time.Duration(a.Transport.Timeout)
	}
	return httpclient.New(ssrf.NewDialer(ssrf.FromEnv(os.Getenv)), a.Metadata.Slug, policy)
}

func findAdapter(root, slug string) (*adapter.File, string, error) {
	files, err := adapter.LoadDir(root)
	if err != nil {
		err = explainMissingRoot(root, err)
		return nil, "", err
	}
	for _, f := range files {
		if f.Adapter.Metadata.Slug == slug {
			return f, filepath.Join(root, filepath.FromSlash(f.Dir)), nil
		}
	}
	return nil, "", fmt.Errorf("no adapter called %q under %s", slug, root)
}

func findTool(a *adapter.Adapter, name string) *adapter.Tool {
	for i := range a.Tools {
		if a.Tools[i].Name == name {
			return &a.Tools[i]
		}
	}
	return nil
}

func selectTools(a *adapter.Adapter, name string) ([]*adapter.Tool, error) {
	if name == "" {
		out := make([]*adapter.Tool, 0, len(a.Tools))
		for i := range a.Tools {
			out = append(out, &a.Tools[i])
		}
		return out, nil
	}
	t := findTool(a, name)
	if t == nil {
		return nil, fmt.Errorf("%s has no tool called %q", a.Metadata.Slug, name)
	}
	return []*adapter.Tool{t}, nil
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}
