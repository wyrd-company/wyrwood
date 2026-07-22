// ---
// relationships: {}
// ---

package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"
)

func TestConfigurationSchemaIsValidJSON(t *testing.T) {
	t.Parallel()

	schema := loadConfigurationSchema(t)
	if schema["$schema"] != "https://json-schema.org/draft/2020-12/schema" {
		t.Fatalf("schema draft = %v", schema["$schema"])
	}
	if additional, ok := schema["additionalProperties"].(bool); !ok || additional {
		t.Fatalf("schema additionalProperties = %v, want false", schema["additionalProperties"])
	}
}

func TestDurationSchemaMatchesPositiveGoDurationSyntax(t *testing.T) {
	t.Parallel()

	schema := loadConfigurationSchema(t)
	definitions := schema["$defs"].(map[string]any)
	duration := definitions["duration"].(map[string]any)
	pattern := regexp.MustCompile(duration["pattern"].(string))

	tests := []struct {
		value string
		want  bool
	}{
		{value: "100ms", want: true},
		{value: "+5s", want: true},
		{value: ".5s", want: true},
		{value: "1.s", want: true},
		{value: "500000us", want: true},
		{value: "500000µs", want: true},
		{value: "500000μs", want: true},
		{value: "1h30m", want: true},
		{value: ".s", want: false},
		{value: "+", want: false},
		{value: "5", want: false},
		{value: "5seconds", want: false},
		{value: "++5s", want: false},
	}
	for _, test := range tests {
		test := test
		t.Run(test.value, func(t *testing.T) {
			t.Parallel()
			parsed, err := time.ParseDuration(test.value)
			runtimeAccepts := err == nil && parsed > 0
			if runtimeAccepts != test.want {
				t.Fatalf("runtime duration acceptance = %v, want %v (error %v)", runtimeAccepts, test.want, err)
			}
			if schemaAccepts := pattern.MatchString(test.value); schemaAccepts != test.want {
				t.Fatalf("schema duration acceptance = %v, want %v", schemaAccepts, test.want)
			}
		})
	}
}

func TestAbsolutePathSchemaExcludesFilesystemRoot(t *testing.T) {
	t.Parallel()

	schema := loadConfigurationSchema(t)
	definitions := schema["$defs"].(map[string]any)
	absolutePath := definitions["absoluteCanonicalPath"].(map[string]any)
	if minimum := absolutePath["minLength"]; minimum != float64(2) {
		t.Fatalf("absoluteCanonicalPath minLength = %v, want 2", minimum)
	}
	if maximum := absolutePath["maxLength"]; maximum != float64(MaximumSocketPathBytes) {
		t.Fatalf("absoluteCanonicalPath maxLength = %v, want %d", maximum, MaximumSocketPathBytes)
	}
}

func TestConsumerFingerprintSchemaMatchesRuntimeBound(t *testing.T) {
	t.Parallel()

	definitions := loadConfigurationSchema(t)["$defs"].(map[string]any)
	consumer := definitions["consumer"].(map[string]any)
	fingerprints := consumer["properties"].(map[string]any)["fingerprints"].(map[string]any)
	if fingerprints["maxItems"] != float64(MaximumFingerprintsPerConsumer) {
		t.Fatalf("fingerprint maxItems = %v, want %d", fingerprints["maxItems"], MaximumFingerprintsPerConsumer)
	}
}

func TestConsumerNameSchemaMatchesRuntimeUnicodeLimit(t *testing.T) {
	t.Parallel()

	schema := loadConfigurationSchema(t)
	definitions := schema["$defs"].(map[string]any)
	consumer := definitions["consumer"].(map[string]any)
	name := consumer["properties"].(map[string]any)["name"].(map[string]any)
	if name["maxLength"] != float64(MaximumConsumerNameCharacters) {
		t.Fatalf("consumer name maxLength = %v, want %d", name["maxLength"], MaximumConsumerNameCharacters)
	}
}

func loadConfigurationSchema(t *testing.T) map[string]any {
	t.Helper()
	path := filepath.Join("..", "..", "docs", "specifications", "assets", "configuration", "configuration.schema.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(schema) error = %v", err)
	}
	var schema map[string]any
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatalf("configuration schema is not valid JSON: %v", err)
	}
	return schema
}
