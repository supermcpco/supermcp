package adapter

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// TestJSONSchemaAgreesWithCorpus validates every generated adapter against
// the published JSON Schema, so the schema and the Go validator cannot
// drift apart.
func TestJSONSchemaAgreesWithCorpus(t *testing.T) {
	root := filepath.Join("..", "..", "adapters")
	if _, err := os.Stat(root); err != nil {
		t.Skip("adapters/ not generated; run make adapters")
	}
	compiler := jsonschema.NewCompiler()
	var schemaDoc any
	if err := json.Unmarshal(JSONSchema, &schemaDoc); err != nil {
		t.Fatal(err)
	}
	if err := compiler.AddResource(SchemaURL, schemaDoc); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile(SchemaURL)
	if err != nil {
		t.Fatalf("schema does not compile: %v", err)
	}
	files, err := LoadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no adapters found")
	}
	for _, f := range files {
		raw, err := jsonMarshal(f.Adapter)
		if err != nil {
			t.Fatalf("%s: %v", f.Dir, err)
		}
		var doc any
		if err := json.NewDecoder(bytes.NewReader(raw)).Decode(&doc); err != nil {
			t.Fatal(err)
		}
		if err := schema.Validate(doc); err != nil {
			t.Errorf("%s: %v", f.Dir, err)
		}
		// The Go validator must agree.
		for _, is := range Validate(f) {
			if is.Severity == SeverityError {
				t.Errorf("%s: go validator: %s", f.Dir, is.Message)
			}
		}
	}
	t.Logf("%d adapters conform to %s", len(files), SchemaURL)
}
