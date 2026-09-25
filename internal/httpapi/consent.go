package httpapi

import (
	"html/template"
	"net/http"

	"github.com/supermcpco/supermcp/internal/mcpserver"
)

// consentData drives the consent page.
type consentData struct {
	RequestID  string
	ClientName string
	OrgName    string
	Redirect   string
	Scopes     []string
	Servers    []*mcpserver.Server
	ServerID   string
	Error      string
	// Status overrides the 400 an error page is served with.
	Status int
}

// The consent page is plain HTML with no scripts: it is shown mid-flow to
// a client that has just opened a browser, and it must render before any
// bundle loads. The strict CSP below is what lets us say that honestly.
var consentTemplate = template.Must(template.New("consent").Parse(`<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>Authorize {{.ClientName}}</title>
<style>
 :root { color-scheme: light dark; --line: #d4d4d8; --tint: #f4f4f5; --fg: #18181b; --bg: #fff; --subtle: #52525b; }
 @media (prefers-color-scheme: dark) { :root { --line: #3f3f46; --tint: #27272a; --fg: #fafafa; --bg: #18181b; --subtle: #a1a1aa; } }
 body { margin: 0; min-height: 100vh; display: grid; place-items: center; padding: 16px;
        font: 14px/1.5 ui-sans-serif, system-ui, sans-serif; background: var(--bg); color: var(--fg); }
 main { width: 100%; max-width: 30rem; border: 1px solid var(--line); border-radius: 12px; padding: 20px 20px 16px; }
 h1 { font-size: 18px; font-weight: 600; margin: 0 0 4px; }
 p { margin: 0 0 12px; color: var(--subtle); }
 ul { margin: 0 0 16px; padding-left: 20px; }
 label { display: block; margin-bottom: 12px; }
 select { width: 100%; padding: 6px 8px; border: 1px solid var(--line); border-radius: 8px; background: var(--bg); color: var(--fg); font: inherit; }
 .row { display: flex; gap: 8px; }
 button { flex: 1; padding: 8px 12px; border-radius: 8px; border: 1px solid var(--line); background: var(--tint); color: var(--fg); font: inherit; cursor: pointer; }
 button.primary { background: var(--fg); color: var(--bg); border-color: var(--fg); }
 .error { border: 1px solid var(--line); background: var(--tint); border-radius: 8px; padding: 8px 12px; margin-bottom: 12px; }
 code { font-family: ui-monospace, monospace; font-size: 0.9em; }
</style></head>
<body><main>
{{if .Error}}<div class="error" role="alert">{{.Error}}</div>{{end}}
<h1>{{.ClientName}} wants to connect</h1>
<p>It will reach <code>{{.Redirect}}</code>{{if .OrgName}} on behalf of {{.OrgName}}{{end}}.</p>
<ul>{{range .Scopes}}<li>{{.}}</li>{{end}}</ul>
<form method="post" action="/oauth/consent">
 <input type="hidden" name="request_id" value="{{.RequestID}}">
 {{if .ServerID}}
   <p>Access is limited to the server this client asked for.</p>
   <input type="hidden" name="server_id" value="{{.ServerID}}">
 {{else}}
   <label>Which MCP server may it use?
     <select name="server_id" required>
       <option value="">Choose a server…</option>
       {{range .Servers}}<option value="{{.ID}}">{{.Name}}</option>{{end}}
     </select>
   </label>
 {{end}}
 <div class="row">
  <button type="submit" name="decision" value="deny">Cancel</button>
  <button class="primary" type="submit" name="decision" value="allow">Allow</button>
 </div>
</form>
</main></body></html>`))

func renderConsent(w http.ResponseWriter, data consentData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	switch {
	case data.Status != 0:
		w.WriteHeader(data.Status)
	case data.Error != "":
		w.WriteHeader(http.StatusBadRequest)
	}
	_ = consentTemplate.Execute(w, data)
}
