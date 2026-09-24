// Package v1 models the legacy v1 adapter JSON format.
//
// It exists only so that the converter (pkg/adapter/v1compat) can read the
// 257 vendored v1 adapters and produce the v2 tree. Nothing at runtime
// depends on this package.
package v1

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Adapter is the loosely typed v1 document. Auth configuration is kept as a
// free-form map because the corpus uses 46 distinct keys across 10 auth
// types; the converter interprets it per type.
type Adapter struct {
	Slug            string                     `json:"slug"`
	Name            string                     `json:"name"`
	Description     string                     `json:"description"`
	Region          string                     `json:"region"`
	Category        string                     `json:"category"`
	Icon            string                     `json:"icon"`
	DocsURL         string                     `json:"docsUrl"`
	RequiredEnvVars []string                   `json:"requiredEnvVars"`
	OptionalEnvVars []string                   `json:"optionalEnvVars,omitempty"`
	Instructions    string                     `json:"instructions,omitempty"`
	Probe           *Probe                     `json:"probe,omitempty"`
	Priority        *int                       `json:"priority,omitempty"`
	SelfHostOnly    bool                       `json:"selfHostOnly,omitempty"`
	Featured        bool                       `json:"featured,omitempty"`
	Connector       Connector                  `json:"connector"`
	Tools           []Tool                     `json:"tools"`
	Extra           map[string]json.RawMessage `json:"-"`
}

// Probe names the tool the catalog health probe calls.
type Probe struct {
	Tool   string         `json:"tool"`
	Params map[string]any `json:"params,omitempty"`
}

// Connector is the v1 upstream definition.
type Connector struct {
	Name            string            `json:"name"`
	Type            string            `json:"type"`
	BaseURL         string            `json:"baseUrl"`
	AuthType        string            `json:"authType"`
	AuthConfig      map[string]any    `json:"authConfig,omitempty"`
	Headers         map[string]string `json:"headers,omitempty"`
	HealthcheckPath string            `json:"healthcheckPath,omitempty"`
	HealthPath      string            `json:"healthPath,omitempty"` // typo in one adapter; honoured by the converter
}

// Tool is one v1 tool entry.
type Tool struct {
	Name            string          `json:"name"`
	Description     string          `json:"description"`
	Parameters      json.RawMessage `json:"parameters"`
	EndpointMapping EndpointMapping `json:"endpointMapping"`
	ResponseMapping json.RawMessage `json:"responseMapping,omitempty"`
	OutputSchema    json.RawMessage `json:"outputSchema,omitempty"`
	UseProxy        bool            `json:"useProxy,omitempty"`
}

// EndpointMapping is the v1 request template. `Method` conflates HTTP
// verbs, GraphQL operations and database operations.
type EndpointMapping struct {
	Method         string            `json:"method"`
	Path           string            `json:"path"`
	QueryParams    map[string]any    `json:"queryParams,omitempty"`
	BodyMapping    any               `json:"bodyMapping,omitempty"` // object, or array (3 tools)
	Headers        map[string]string `json:"headers,omitempty"`
	BodyEncoding   string            `json:"bodyEncoding,omitempty"`
	BodyTemplate   string            `json:"bodyTemplate,omitempty"`
	StaticResponse string            `json:"staticResponse,omitempty"`
	ExposeHeaders  []string          `json:"exposeHeaders,omitempty"`
}

// Known top-level keys. Anything else is reported by the converter rather
// than silently dropped.
var knownTopLevelKeys = map[string]bool{
	"slug": true, "name": true, "description": true, "region": true, "category": true,
	"icon": true, "docsUrl": true, "requiredEnvVars": true, "optionalEnvVars": true,
	"instructions": true, "probe": true, "priority": true, "selfHostOnly": true,
	"featured": true, "connector": true, "tools": true,
}

// Parse decodes one v1 adapter. Unknown top-level keys are collected into
// Extra so the converter can report them.
func Parse(data []byte) (*Adapter, error) {
	var a Adapter
	if err := json.Unmarshal(data, &a); err != nil {
		return nil, err
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	for k, v := range raw {
		if !knownTopLevelKeys[k] {
			if a.Extra == nil {
				a.Extra = map[string]json.RawMessage{}
			}
			a.Extra[k] = v
		}
	}
	return &a, nil
}

// File is one adapter together with where it came from.
type File struct {
	Region  string // directory name, which is authoritative over the region field
	Path    string
	Adapter *Adapter
	Raw     []byte
}

// LoadDir reads every <region>/<slug>.json under root, sorted by path.
// Reads go through os.Root so a symlink inside the corpus cannot escape it.
func LoadDir(root string) ([]File, error) {
	r, err := os.OpenRoot(root)
	if err != nil {
		return nil, err
	}
	defer func() { _ = r.Close() }()
	var files []File
	err = fs.WalkDir(r.FS(), ".", func(rel string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(rel, ".json") {
			return nil
		}
		p := filepath.Join(root, filepath.FromSlash(rel))
		parts := strings.Split(rel, "/")
		if len(parts) != 2 {
			return nil // only <region>/<slug>.json
		}
		data, err := r.ReadFile(rel)
		if err != nil {
			return err
		}
		a, err := Parse(data)
		if err != nil {
			return fmt.Errorf("%s: %w", rel, err)
		}
		files = append(files, File{Region: parts[0], Path: p, Adapter: a, Raw: data})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files, nil
}
