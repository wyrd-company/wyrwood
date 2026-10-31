// ---
// relationships:
//   verifies: configuration
// ---

package config

import (
	"encoding/json"
	"testing"

	"github.com/wyrd-company/wyrwood/internal/schematest"
	"gopkg.in/yaml.v3"
)

func TestControllerLocalAgentConfiguration(t *testing.T) {
	schema := schematest.Compile(t, schematest.ControllerConfiguration)
	for _, sample := range []struct {
		suffix  string
		enabled bool
		valid   bool
	}{
		{"", false, true},
		{"local-agent: {}\n", false, true},
		{"local-agent:\n  enabled: true\n", true, true},
		{"local-agent:\n  enabled: false\n", false, true},
		{"local-agent:\n  enabled: invalid\n", false, false},
		{"local-agent:\n  enable: true\n", false, false},
	} {
		t.Run(sample.suffix, func(t *testing.T) {
			data := []byte(minimalController + sample.suffix)
			parsed, err := ParseController(data)
			if (err == nil) != sample.valid {
				t.Fatalf("parse error = %v", err)
			}
			if err == nil && parsed.LocalAgent != sample.enabled {
				t.Fatalf("enabled = %v", parsed.LocalAgent)
			}
			var document any
			if err := yaml.Unmarshal(data, &document); err != nil {
				t.Fatal(err)
			}
			encoded, _ := json.Marshal(document)
			if err := schematest.Validate(schema, encoded); (err == nil) != sample.valid {
				t.Fatalf("schema error = %v", err)
			}
		})
	}
}
