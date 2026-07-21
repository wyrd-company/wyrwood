// ---
// relationships: {}
// ---

package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestConfigurationSchemaIsValidJSON(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", "docs", "specifications", "assets", "configuration", "configuration.schema.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(schema) error = %v", err)
	}
	var schema map[string]any
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatalf("configuration schema is not valid JSON: %v", err)
	}
	if schema["$schema"] != "https://json-schema.org/draft/2020-12/schema" {
		t.Fatalf("schema draft = %v", schema["$schema"])
	}
	if additional, ok := schema["additionalProperties"].(bool); !ok || additional {
		t.Fatalf("schema additionalProperties = %v, want false", schema["additionalProperties"])
	}
}
