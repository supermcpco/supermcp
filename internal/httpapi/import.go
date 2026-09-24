package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/supermcpco/supermcp/internal/audit"
	"github.com/supermcpco/supermcp/internal/authz"
	"github.com/supermcpco/supermcp/internal/connector"
	"github.com/supermcpco/supermcp/internal/parser"
	"github.com/supermcpco/supermcp/pkg/adapter"
)

// importFetchTimeout bounds the fetch of a document URL, and the
// introspection of a GraphQL endpoint. The caller is holding a request
// open while it happens, so it is short.
const importFetchTimeout = 20 * time.Second

// importFormats is what the format field accepts. "auto" is the default:
// the server works the format out and says so rather than guessing when
// it cannot tell.
const importFormats = "auto,openapi,postman,curl,graphql"

// importFetcher is the part of the upstream HTTP client this handler
// needs. It is declared here, at the consumer, so the handler cannot
// accidentally be given a client that does not go through the SSRF guard.
type importFetcher interface {
	Do(req *http.Request) (*http.Response, error)
}

// importFetch returns the client an import URL is fetched through.
//
// It is the SSRF-guarded client and never http.DefaultClient: an import
// URL is caller-supplied, and a server fetching one on their behalf is
// precisely the request an attacker would like to make. A nil field
// returns a nil interface rather than a non-nil interface holding a nil
// pointer, so the caller's check works.
func (d Deps) importFetch() importFetcher {
	if d.ImportFetch == nil {
		return nil
	}
	return d.ImportFetch
}

type importInput struct {
	Body struct {
		Format      string            `json:"format,omitempty" enum:"auto,openapi,postman,curl,graphql" doc:"What the document is. Left out, the server works it out from the document and refuses rather than guessing when it cannot tell"`
		Document    string            `json:"document,omitempty" doc:"The description itself: an OpenAPI 3.0 or 3.1 document, a Postman collection v2.1, a curl command, or a GraphQL introspection response"`
		URL         string            `json:"url,omitempty" format:"uri" doc:"Where to fetch the document from, instead of sending it inline. With format graphql it is the endpoint to introspect"`
		Name        string            `json:"name,omitempty" doc:"Connector name; defaults to the document's title"`
		Slug        string            `json:"slug,omitempty" pattern:"^[a-z0-9]+(-[a-z0-9]+)*$" doc:"Prefix for the generated tool names; defaults to a slug of the title"`
		ServerURL   string            `json:"serverUrl,omitempty" doc:"Base URL to call, when the document lists several or templates one. For GraphQL it is the endpoint the tools post to"`
		Headers     map[string]string `json:"headers,omitempty" doc:"Headers to introspect a GraphQL endpoint with. They are used for the introspection request and are not stored"`
		Credentials map[string]string `json:"credentials,omitempty" doc:"Values for the credentials the document implies"`
		DryRun      bool              `json:"dryRun,omitempty" doc:"Report what would be created without creating it"`
	}
}

type importOutput struct {
	Body struct {
		DryRun    bool                   `json:"dryRun"`
		Connector *connectorDTO          `json:"connector,omitempty"`
		Preview   *importPreview         `json:"preview,omitempty"`
		Findings  []parser.ImportFinding `json:"findings" nullable:"false"`
		Warnings  []string               `json:"warnings,omitempty" nullable:"false"`
	}
}

// importPreview is what a dry run returns: everything the create would
// have written, and nothing written.
type importPreview struct {
	Name        string              `json:"name"`
	Format      string              `json:"format"`
	Transport   string              `json:"transport"`
	BaseURL     string              `json:"baseUrl"`
	AuthType    string              `json:"authType"`
	Credentials []string            `json:"credentials" nullable:"false"`
	Tools       []importToolPreview `json:"tools" nullable:"false"`
}

type importToolPreview struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Method      string `json:"method"`
	Path        string `json:"path"`
	ReadOnly    bool   `json:"readOnly,omitempty"`
	Destructive bool   `json:"destructive,omitempty"`
}

func (d Deps) importRoutes(api huma.API) {
	huma.Register(api, huma.Operation{OperationID: "connectors-import", Method: http.MethodPost, Path: "/api/v1/connectors/import",
		Summary: "Import an API description as a connector", Tags: []string{"connectors"}, Security: sessionSecurity},
		func(ctx context.Context, in *importInput) (*importOutput, error) {
			p, err := d.require(ctx, authz.ConnectorsCreate, authz.Resource{})
			if err != nil {
				return nil, err
			}

			doc, source, format, err := d.importDocument(ctx, in)
			if err != nil {
				d.adminFailed(ctx, "connector.import", "connector", in.Body.URL, err)
				return nil, err
			}

			a, findings, err := convertImport(doc, format, in)
			parser.SortFindings(findings)
			if err != nil {
				d.adminFailed(ctx, "connector.import", "connector", source, err)
				return nil, huma.Error400BadRequest("the document cannot be imported: "+err.Error(), findingErrors(findings)...)
			}

			out := &importOutput{}
			out.Body.DryRun = in.Body.DryRun
			out.Body.Findings = findings
			if findings == nil {
				out.Body.Findings = []parser.ImportFinding{}
			}

			// The validator is the same contract the catalogue is held to;
			// a document that cannot satisfy it is refused here rather than
			// stored and discovered later by a tools/list.
			var blocking []error
			for _, issue := range adapter.Validate(&adapter.File{Adapter: a}) {
				if issue.Severity == adapter.SeverityError {
					blocking = append(blocking, &huma.ErrorDetail{Location: issue.Rule, Message: issue.Message})
					continue
				}
				out.Body.Warnings = append(out.Body.Warnings, issue.Rule+": "+issue.Message)
			}

			if in.Body.DryRun {
				out.Body.Preview = previewOf(a, format)
				// A preview that says nothing about the validator's
				// refusals is a preview that promises an import which then
				// fails. Report them here, as the rough edges they are.
				for _, b := range blocking {
					var detail *huma.ErrorDetail
					if errors.As(b, &detail) {
						out.Body.Warnings = append(out.Body.Warnings,
							"this would be refused on import — "+detail.Location+": "+detail.Message)
					}
				}
				return out, nil
			}
			if parser.HasBlockers(findings) {
				return nil, huma.Error422UnprocessableEntity("the document needs a decision before it can be imported; preview it with dryRun to see the findings", findingErrors(findings)...)
			}
			if len(blocking) > 0 {
				return nil, huma.Error422UnprocessableEntity("the connector the document produces is not valid", blocking...)
			}

			c, err := d.Connectors.Create(ctx, p.OrgID, connector.CreateInput{
				Name:         a.Metadata.Name,
				Transport:    a.Transport,
				Auth:         a.Auth,
				Instructions: a.Instructions,
				Tools:        a.Tools,
				Credentials:  in.Body.Credentials,
				CreatedBy:    p.ID,
			})
			if err != nil {
				d.adminFailed(ctx, "connector.import", "connector", a.Metadata.Name, err)
				return nil, humaErr(err)
			}
			dto := connectorToDTO(c)
			d.admin(ctx, "connector.import", "connector", c.ID, c.Name, audit.Created(dto))
			out.Body.Connector = &dto
			return out, nil
		})
}

// convertImport runs the importer the format names. Each returns the same
// three things, so this is the whole of the difference between them here.
func convertImport(doc []byte, format parser.Format, in *importInput) (*adapter.Adapter, []parser.ImportFinding, error) {
	opts := parser.Options{
		Slug:      in.Body.Slug,
		Name:      in.Body.Name,
		ServerURL: in.Body.ServerURL,
	}
	switch format {
	case parser.FormatPostman:
		return parser.FromPostman(doc, opts)
	case parser.FormatCurl:
		return parser.FromCurl(doc, opts)
	case parser.FormatGraphQL:
		if opts.ServerURL == "" {
			// An introspection response does not say where it came from.
			// When it was fetched, the URL it was fetched from is the
			// endpoint the tools will post to.
			opts.ServerURL = strings.TrimSpace(in.Body.URL)
		}
		return parser.FromGraphQL(doc, parser.GraphQLOptions{Options: opts, Headers: in.Body.Headers})
	default:
		return parser.FromOpenAPI(doc, opts)
	}
}

// importDocument returns the document, a short description of where it
// came from for the audit trail, and the format it is to be read as.
//
// Detection is honest about doubt: a document that could be read two ways
// is refused with the reason, because the importers disagree about what a
// document means and a wrong guess produces a connector that looks
// finished and calls the wrong thing.
func (d Deps) importDocument(ctx context.Context, in *importInput) ([]byte, string, parser.Format, error) {
	inline := strings.TrimSpace(in.Body.Document)
	chosen, named := parser.ParseFormat(in.Body.Format)
	if in.Body.Format != "" && in.Body.Format != "auto" && !named {
		return nil, "", "", huma.Error400BadRequest("format must be one of " + importFormats)
	}

	var (
		doc    []byte
		source string
		err    error
	)
	switch {
	case inline != "" && in.Body.URL != "":
		return nil, "", "", huma.Error400BadRequest("send either document or url, not both")
	case inline != "":
		doc, source = []byte(in.Body.Document), "inline document"
	case in.Body.URL != "":
		source = in.Body.URL
		if chosen == parser.FormatCurl {
			// A command is not something that lives at a URL, and
			// fetching one and running the curl importer over whatever
			// came back would be a way to make this server read a page and
			// call it a request.
			return nil, source, "", huma.Error400BadRequest("a curl command has to be sent inline; there is nothing at a URL to fetch one from")
		}
		if named && chosen == parser.FormatGraphQL {
			// A GraphQL endpoint does not serve its schema; it answers a
			// question about it. Asking is the only way to fetch one.
			doc, err = d.introspectGraphQL(ctx, in.Body.URL, in.Body.Headers)
		} else {
			doc, err = d.fetchDocument(ctx, in.Body.URL)
		}
		if err != nil {
			return nil, source, "", err
		}
	default:
		return nil, "", "", huma.Error400BadRequest("a document or a url is required")
	}

	if named {
		return doc, source, chosen, nil
	}
	detected, why := parser.Detect(doc)
	if detected == parser.FormatUnknown {
		return nil, source, "", huma.Error400BadRequest("the format of this document cannot be worked out, so say which it is: " + why)
	}
	return doc, source, detected, nil
}

// introspectGraphQL asks a live GraphQL endpoint to describe itself.
//
// Everything about this is as narrow as fetchDocument, and for the same
// reason: the URL is caller-supplied, so the request goes through the
// guarded client, under a deadline, with a bounded read. The headers are
// the caller's own and are used for this one request; nothing stores
// them, which is why the adapter declares a credential for the sign-in
// they imply rather than copying the value across.
func (d Deps) introspectGraphQL(ctx context.Context, raw string, headers map[string]string) ([]byte, error) {
	client := d.importFetch()
	if client == nil {
		return nil, huma.Error501NotImplemented("this server cannot reach a GraphQL endpoint; paste the introspection response instead")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, huma.Error400BadRequest("url must be an absolute http or https URL")
	}
	body, err := json.Marshal(map[string]string{"query": parser.IntrospectionQuery})
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, importFetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, huma.Error400BadRequest("url is not usable: " + err.Error())
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	for name, value := range headers {
		if strings.TrimSpace(name) == "" {
			continue
		}
		req.Header.Set(name, value)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, huma.Error400BadRequest("the endpoint could not be reached: " + err.Error())
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, huma.Error400BadRequest("the endpoint answered " + resp.Status + " to an introspection query; if it needs credentials, send them as headers")
	}
	out, err := io.ReadAll(io.LimitReader(resp.Body, int64(parser.DefaultMaxBytes)+1))
	if err != nil {
		return nil, huma.Error400BadRequest("the endpoint's answer could not be read: " + err.Error())
	}
	if len(out) > parser.DefaultMaxBytes {
		return nil, huma.Error400BadRequest("the endpoint's schema is larger than this server will import")
	}
	if len(out) == 0 {
		return nil, huma.Error400BadRequest("the endpoint answered an introspection query with nothing")
	}
	return out, nil
}

// fetchDocument retrieves a document over HTTP. Everything about this
// function is deliberately narrow: the guarded client, a deadline, a
// status check and a bounded read.
func (d Deps) fetchDocument(ctx context.Context, raw string) ([]byte, error) {
	client := d.importFetch()
	if client == nil {
		return nil, huma.Error501NotImplemented("this server cannot fetch import URLs; send the document inline")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, huma.Error400BadRequest("url must be an absolute http or https URL")
	}
	ctx, cancel := context.WithTimeout(ctx, importFetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, huma.Error400BadRequest("url is not usable: " + err.Error())
	}
	req.Header.Set("Accept", "application/json, application/yaml;q=0.9, text/yaml;q=0.8, */*;q=0.1")
	resp, err := client.Do(req)
	if err != nil {
		return nil, huma.Error400BadRequest("the document could not be fetched: " + err.Error())
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, huma.Error400BadRequest("the document URL answered " + resp.Status)
	}
	// One byte over the limit is enough to know it is over it.
	doc, err := io.ReadAll(io.LimitReader(resp.Body, int64(parser.DefaultMaxBytes)+1))
	if err != nil {
		return nil, huma.Error400BadRequest("the document could not be read: " + err.Error())
	}
	if len(doc) > parser.DefaultMaxBytes {
		return nil, huma.Error400BadRequest("the document is larger than this server will import")
	}
	if len(doc) == 0 {
		return nil, huma.Error400BadRequest("the document URL returned nothing")
	}
	return doc, nil
}

// reGraphQLOperation reads the operation name off a generated document,
// which is the schema field the tool calls.
var reGraphQLOperation = regexp.MustCompile(`^(?:query|mutation)\s+([A-Za-z_][A-Za-z0-9_]*)`)

func previewOf(a *adapter.Adapter, format parser.Format) *importPreview {
	p := &importPreview{
		Name:        a.Metadata.Name,
		Format:      string(format),
		Transport:   string(a.Transport.Type),
		BaseURL:     a.Transport.BaseURL,
		AuthType:    string(a.Auth.Type),
		Credentials: append([]string{}, a.Credentials.Keys...),
		Tools:       make([]importToolPreview, 0, len(a.Tools)),
	}
	for i := range a.Tools {
		t := &a.Tools[i]
		item := importToolPreview{Name: t.Name, Description: t.Description, Method: t.Operation.Method, Path: t.Operation.Path}
		if a.Transport.Type == adapter.TransportGraphQL {
			// A GraphQL tool has no method and no path. What it does is the
			// operation kind and the field it names, so the preview shows
			// that in the same two columns.
			item.Method = t.Operation.Kind
			if m := reGraphQLOperation.FindStringSubmatch(t.Operation.Document); m != nil {
				item.Path = m[1]
			}
		}
		if t.Annotations != nil {
			item.ReadOnly = t.Annotations.ReadOnlyHint != nil && *t.Annotations.ReadOnlyHint
			item.Destructive = t.Annotations.DestructiveHint != nil && *t.Annotations.DestructiveHint
		}
		p.Tools = append(p.Tools, item)
	}
	return p
}

// findingErrors renders the findings that stand in the way as error
// details, so a client sees why the import stopped without asking again.
func findingErrors(findings []parser.ImportFinding) []error {
	var out []error
	for _, f := range findings {
		if f.Level != parser.Blocker {
			continue
		}
		location := f.Path
		if f.Operation != "" {
			location = f.Operation + ": " + f.Path
		}
		out = append(out, &huma.ErrorDetail{Location: location, Message: f.Message})
	}
	return out
}
