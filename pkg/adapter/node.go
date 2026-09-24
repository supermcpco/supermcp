package adapter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Node wraps a yaml.Node so free-form structures keep their authored key
// order through YAML and serialise as plain values in JSON.
type Node struct {
	N *yaml.Node
}

func (n Node) IsZero() bool { return n.N == nil }

func (n Node) MarshalYAML() (any, error) {
	if n.N == nil {
		return nil, nil
	}
	return n.N, nil
}

func (n *Node) UnmarshalYAML(x *yaml.Node) error {
	n.N = x
	return nil
}

func (n Node) MarshalJSON() ([]byte, error) {
	if n.N == nil {
		return []byte("null"), nil
	}
	v, err := NodeValue(n.N)
	if err != nil {
		return nil, err
	}
	return jsonMarshal(v)
}

// Value decodes the node into a Go value (maps become map[string]any with
// no order guarantee; use NodeValue for the ordered form).
func (n Node) Value() (any, error) {
	if n.N == nil {
		return nil, nil
	}
	return NodeValue(n.N)
}

// NodeFromJSON parses JSON into an order-preserving Node.
func NodeFromJSON(data []byte) (*Node, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, nil
	}
	var y yaml.Node
	if err := yaml.Unmarshal(data, &y); err != nil {
		return nil, err
	}
	doc := &y
	if doc.Kind == yaml.DocumentNode && len(doc.Content) == 1 {
		doc = doc.Content[0]
	}
	normaliseJSONNode(doc)
	return &Node{N: doc}, nil
}

// NodeFromValue encodes a Go value into a Node.
func NodeFromValue(v any) (*Node, error) {
	var y yaml.Node
	if err := y.Encode(v); err != nil {
		return nil, err
	}
	return &Node{N: &y}, nil
}

// normaliseJSONNode clears the flow style yaml.v3 assigns to JSON input so
// the document is emitted in block style, and strips explicit quoting on
// keys.
func normaliseJSONNode(n *yaml.Node) {
	n.Style = 0
	if n.Kind == yaml.ScalarNode && n.Tag == "!!str" && needsQuoting(n.Value) {
		n.Style = yaml.DoubleQuotedStyle
	}
	if n.Kind == yaml.ScalarNode && n.Tag == "!!str" && strings.Contains(n.Value, "\n") {
		n.Style = yaml.LiteralStyle
	}
	for _, c := range n.Content {
		normaliseJSONNode(c)
	}
}

// needsQuoting reports whether a string scalar would be misread as another
// YAML type when emitted plain.
func needsQuoting(s string) bool {
	if s == "" {
		return true
	}
	switch strings.ToLower(s) {
	case "true", "false", "yes", "no", "on", "off", "null", "~", "y", "n":
		return true
	}
	if _, err := strconv.ParseFloat(s, 64); err == nil {
		return true
	}
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0o") {
		return true
	}
	return false
}

// NodeValue converts a yaml.Node into Go values. Mappings become
// map[string]any; ordering is carried separately by callers that need it.
func NodeValue(n *yaml.Node) (any, error) {
	switch n.Kind {
	case yaml.DocumentNode:
		if len(n.Content) == 0 {
			return nil, nil
		}
		return NodeValue(n.Content[0])
	case yaml.MappingNode:
		m := make(map[string]any, len(n.Content)/2)
		for i := 0; i+1 < len(n.Content); i += 2 {
			v, err := NodeValue(n.Content[i+1])
			if err != nil {
				return nil, err
			}
			m[n.Content[i].Value] = v
		}
		return m, nil
	case yaml.SequenceNode:
		s := make([]any, 0, len(n.Content))
		for _, c := range n.Content {
			v, err := NodeValue(c)
			if err != nil {
				return nil, err
			}
			s = append(s, v)
		}
		return s, nil
	case yaml.ScalarNode:
		switch n.Tag {
		case "!!str":
			return n.Value, nil
		case "!!int":
			i, err := strconv.ParseInt(n.Value, 0, 64)
			if err != nil {
				return nil, err
			}
			return i, nil
		case "!!float":
			return strconv.ParseFloat(n.Value, 64)
		case "!!bool":
			return strconv.ParseBool(n.Value)
		case "!!null":
			return nil, nil
		default:
			return n.Value, nil
		}
	case yaml.AliasNode:
		return nil, fmt.Errorf("line %d: YAML aliases are not allowed", n.Line)
	}
	return nil, fmt.Errorf("line %d: unsupported node kind %d", n.Line, n.Kind)
}

// WalkStrings visits every string scalar under n and replaces its value
// with fn(value). Mapping keys are left alone.
func WalkStrings(n *yaml.Node, fn func(string) string) {
	if n == nil {
		return
	}
	switch n.Kind {
	case yaml.ScalarNode:
		if n.Tag == "!!str" {
			n.Value = fn(n.Value)
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			WalkStrings(n.Content[i+1], fn)
		}
	default:
		for _, c := range n.Content {
			WalkStrings(c, fn)
		}
	}
}

// MapGet returns the value node for key in a mapping node.
func MapGet(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

// MapKeys returns the keys of a mapping node in order.
func MapKeys(n *yaml.Node) []string {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	keys := make([]string, 0, len(n.Content)/2)
	for i := 0; i+1 < len(n.Content); i += 2 {
		keys = append(keys, n.Content[i].Value)
	}
	return keys
}

// jsonUnmarshalOrdered decodes JSON keeping numbers as json.Number so that
// re-encoding does not alter their text.
func jsonUnmarshalOrdered(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	return dec.Decode(v)
}

func jsonMarshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// scalar builds a string scalar node (test helper, exported for _test use).
func scalar(s string) *yaml.Node { return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: s} }

// UnmarshalJSON parses JSON into an order-preserving node. Connector
// definitions round-trip through JSONB, so this must exist: without it
// every free-form structure would come back empty.
func (n *Node) UnmarshalJSON(data []byte) error {
	out, err := NodeFromJSON(data)
	if err != nil {
		return err
	}
	if out == nil {
		n.N = nil
		return nil
	}
	n.N = out.N
	return nil
}
