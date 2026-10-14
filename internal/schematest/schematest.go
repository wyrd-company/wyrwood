// ---
// relationships:
//   verifies:
//     - operational-events
//     - agent-controller-protocol
//     - policy
//     - configuration
// ---

// Package schematest compiles the JSON Schema assets in docs/specifications
// so tests can validate Go serializations against the authoritative contract.
package schematest

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// Asset names a schema asset relative to docs/specifications/assets.
type Asset string

const (
	OperationalEvent        Asset = "operational-events/operational-event.schema.json"
	AgentControllerMessage  Asset = "agent-controller-protocol/message.schema.json"
	Policy                  Asset = "policy/policy.schema.json"
	AgentConfiguration      Asset = "configuration/agent.schema.json"
	ControllerConfiguration Asset = "configuration/controller.schema.json"
)

var allAssets = []Asset{OperationalEvent, AgentControllerMessage, Policy, AgentConfiguration, ControllerConfiguration}

// Root returns the repository root.
func Root() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

// Path returns the absolute path of a schema asset.
func Path(asset Asset) string {
	return filepath.Join(Root(), "docs", "specifications", "assets", filepath.FromSlash(string(asset)))
}

// Load returns the raw decoded schema document.
func Load(t testing.TB, asset Asset) map[string]any {
	t.Helper()
	data, err := os.ReadFile(Path(asset))
	if err != nil {
		t.Fatalf("read schema %s: %v", asset, err)
	}
	var document map[string]any
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatalf("decode schema %s: %v", asset, err)
	}
	return document
}

// Compile compiles one schema asset with every other asset registered so
// cross-asset references resolve by identifier.
func Compile(t testing.TB, asset Asset) *jsonschema.Schema {
	t.Helper()
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	var target string
	for _, candidate := range allAssets {
		identifier, _ := Load(t, candidate)["$id"].(string)
		if identifier == "" {
			t.Fatalf("schema %s has no $id", candidate)
		}
		data, err := os.ReadFile(Path(candidate))
		if err != nil {
			t.Fatalf("read schema %s: %v", candidate, err)
		}
		document, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
		if err != nil {
			t.Fatalf("decode schema %s: %v", candidate, err)
		}
		if err := compiler.AddResource(identifier, document); err != nil {
			t.Fatalf("register schema %s: %v", candidate, err)
		}
		if candidate == asset {
			target = identifier
		}
	}
	schema, err := compiler.Compile(target)
	if err != nil {
		t.Fatalf("compile schema %s: %v", asset, err)
	}
	return schema
}

// Validate validates JSON bytes against a compiled schema.
func Validate(schema *jsonschema.Schema, data []byte) error {
	value, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		return err
	}
	return schema.Validate(value)
}
