package adapter

import (
	_ "embed"
)

// JSONSchema is the published JSON Schema for adapter documents. It is
// served at /schema/adapter/v2.json and referenced by the yaml-language-
// server comment on every adapter file.
//
//go:embed schema/adapter-v2.json
var JSONSchema []byte
