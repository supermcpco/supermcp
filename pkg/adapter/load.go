package adapter

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// FileName is the adapter document inside an adapter directory.
const FileName = "adapter.yaml"

// SchemaComment is the first line of every adapter file; editors use it for
// completion and the linter checks it.
const SchemaComment = "# yaml-language-server: $schema=" + SchemaURL

// Parse decodes one adapter document. It rejects anchors, aliases and
// custom tags, and checks apiVersion/kind before anything else.
func Parse(data []byte) (*Adapter, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	if err := rejectUnsafeYAML(&doc); err != nil {
		return nil, err
	}
	var a Adapter
	if err := doc.Decode(&a); err != nil {
		return nil, err
	}
	if a.APIVersion != APIVersion {
		return nil, fmt.Errorf("apiVersion is %q, want %q", a.APIVersion, APIVersion)
	}
	if a.Kind != KindName {
		return nil, fmt.Errorf("kind is %q, want %q", a.Kind, KindName)
	}
	return &a, nil
}

func rejectUnsafeYAML(n *yaml.Node) error {
	if n.Kind == yaml.AliasNode {
		return fmt.Errorf("line %d: YAML aliases are not allowed", n.Line)
	}
	if n.Anchor != "" {
		return fmt.Errorf("line %d: YAML anchors are not allowed", n.Line)
	}
	if strings.HasPrefix(n.Tag, "!") && !strings.HasPrefix(n.Tag, "!!") {
		return fmt.Errorf("line %d: custom tag %q is not allowed", n.Line, n.Tag)
	}
	for _, c := range n.Content {
		if err := rejectUnsafeYAML(c); err != nil {
			return err
		}
	}
	return nil
}

// Marshal renders an adapter as YAML with the schema comment on top.
func Marshal(a *Adapter) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString(SchemaComment)
	buf.WriteByte('\n')
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(a); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// File is an adapter and where it was read from.
type File struct {
	Dir     string // adapters/<region>/<slug>
	Region  string // directory name
	Adapter *Adapter
}

// LoadFile reads a single adapter.yaml.
func LoadFile(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	a, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	dir := filepath.Dir(path)
	return &File{Dir: dir, Region: filepath.Base(filepath.Dir(dir)), Adapter: a}, nil
}

// LoadDir reads every <region>/<slug>/adapter.yaml under root.
func LoadDir(root string) ([]*File, error) {
	return LoadFS(os.DirFS(root), ".")
}

// LoadFS reads adapters from any fs.FS (including an embed.FS).
func LoadFS(fsys fs.FS, root string) ([]*File, error) {
	var files []*File
	err := fs.WalkDir(fsys, root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || d.Name() != FileName {
			return nil
		}
		data, err := fs.ReadFile(fsys, p)
		if err != nil {
			return err
		}
		a, err := Parse(data)
		if err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		dir := filepath.ToSlash(filepath.Dir(p))
		files = append(files, &File{Dir: dir, Region: filepath.Base(filepath.Dir(dir)), Adapter: a})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Dir < files[j].Dir })
	return files, nil
}

// ContentHash is the v2 content-addressed version: sha256 over the
// canonical JSON of the parts that get copied into an installed connector,
// first 12 hex chars. Tools are sorted by name (byte order).
func ContentHash(a *Adapter) (string, error) {
	tools := make([]Tool, len(a.Tools))
	copy(tools, a.Tools)
	sort.Slice(tools, func(i, j int) bool { return tools[i].Name < tools[j].Name })
	doc := map[string]any{
		"instructions": a.Instructions,
		"transport":    map[string]any{"type": a.Transport.Type, "baseUrl": a.Transport.BaseURL, "dsn": a.Transport.DSN},
		"auth":         map[string]any{"type": a.Auth.Type},
		"tools":        tools,
	}
	b, err := canonicalJSON(doc)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])[:12], nil
}

// canonicalJSON marshals with sorted keys. Struct fields marshal in
// declaration order, so we round-trip through a generic value first.
func canonicalJSON(v any) ([]byte, error) {
	raw, err := jsonMarshal(v)
	if err != nil {
		return nil, err
	}
	var generic any
	if err := jsonUnmarshalOrdered(raw, &generic); err != nil {
		return nil, err
	}
	return jsonMarshal(sortKeys(generic))
}

func sortKeys(v any) any {
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out := make(orderedJSON, 0, len(keys))
		for _, k := range keys {
			out = append(out, kv{k, sortKeys(x[k])})
		}
		return out
	case []any:
		for i := range x {
			x[i] = sortKeys(x[i])
		}
		return x
	}
	return v
}

type kv struct {
	k string
	v any
}

// orderedJSON marshals as an object in slice order.
type orderedJSON []kv

func (o orderedJSON) MarshalJSON() ([]byte, error) {
	buf := []byte{'{'}
	for i, e := range o {
		if i > 0 {
			buf = append(buf, ',')
		}
		kb, _ := jsonMarshal(e.k)
		vb, err := jsonMarshal(e.v)
		if err != nil {
			return nil, err
		}
		buf = append(buf, kb...)
		buf = append(buf, ':')
		buf = append(buf, vb...)
	}
	return append(buf, '}'), nil
}

// MarshalJSON renders an adapter as JSON (no HTML escaping, ordered maps
// kept in authored order).
func MarshalJSON(a *Adapter) ([]byte, error) {
	return jsonMarshal(a)
}
