//go:build linux

// ---
// relationships:
//   verifies: control-interface
// ---

package control

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestControlSchemaIsClosedAndCarriesImplementationBounds(t *testing.T) {
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source")
	}
	path := filepath.Join(filepath.Dir(source), "..", "..", "docs", "specifications", "assets", "control-interface", "control-message.schema.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(): %v", err)
	}
	var schema map[string]any
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatalf("schema is not JSON: %v", err)
	}
	definitions, ok := schema["$defs"].(map[string]any)
	if !ok {
		t.Fatal("schema definitions are missing")
	}
	request := definitions["request"].(map[string]any)
	variants := request["oneOf"].([]any)
	for _, variant := range variants {
		object := variant.(map[string]any)
		if object["additionalProperties"] != false {
			t.Fatal("request schema is not closed")
		}
	}
	response := definitions["response"].(map[string]any)
	if response["additionalProperties"] != false {
		t.Fatal("response schema is not closed")
	}
	properties := response["properties"].(map[string]any)
	keys := properties["keys"].(map[string]any)["properties"].(map[string]any)["keys"].(map[string]any)
	if keys["maxItems"] != float64(MaximumProjectedKeys) {
		t.Fatalf("key maximum = %v", keys["maxItems"])
	}
	status := properties["status"].(map[string]any)["properties"].(map[string]any)["consumers"].(map[string]any)
	if status["maxItems"] != float64(MaximumProjectedPeers) {
		t.Fatalf("consumer maximum = %v", status["maxItems"])
	}
	eventRequest := variants[1].(map[string]any)["properties"].(map[string]any)["limit"].(map[string]any)
	if eventRequest["maximum"] != float64(MaximumEventLimit) {
		t.Fatalf("event maximum = %v", eventRequest["maximum"])
	}
}
