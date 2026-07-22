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
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/wyrd-company/wyrwood/internal/config"
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
	if len(variants) != 8 {
		t.Fatalf("request variants = %d, want 8", len(variants))
	}
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
	if status["maxItems"] != float64(MaximumProjectedConsumers) {
		t.Fatalf("consumer maximum = %v", status["maxItems"])
	}
	consumer := definitions["consumer-status"].(map[string]any)
	name := consumer["properties"].(map[string]any)["name"].(map[string]any)
	if name["maxLength"] != float64(MaximumConsumerNameCharacters) || MaximumConsumerNameCharacters != config.MaximumConsumerNameCharacters {
		t.Fatalf("consumer name maximum = %v", name["maxLength"])
	}
	eventRequest := variants[1].(map[string]any)["properties"].(map[string]any)["limit"].(map[string]any)
	if eventRequest["maximum"] != float64(MaximumEventLimit) {
		t.Fatalf("event maximum = %v", eventRequest["maximum"])
	}
	configurationRequest := variants[2].(map[string]any)["properties"].(map[string]any)["limit"].(map[string]any)
	if configurationRequest["maximum"] != float64(MaximumConfigurationPageSize) {
		t.Fatalf("configuration page maximum = %v", configurationRequest["maximum"])
	}
	wantOperations := []string{"apply", "keys", "status", "events", "configuration", "configuration", "set-upstream", "set-timeouts", "put-consumer", "retire-consumer"}
	var schemaOperations []string
	for _, raw := range variants {
		properties := raw.(map[string]any)["properties"].(map[string]any)
		operation := properties["operation"].(map[string]any)
		if constant, ok := operation["const"].(string); ok {
			schemaOperations = append(schemaOperations, constant)
		} else {
			for _, value := range operation["enum"].([]any) {
				schemaOperations = append(schemaOperations, value.(string))
			}
		}
	}
	if !reflect.DeepEqual(schemaOperations, wantOperations) {
		t.Fatalf("request operations = %v, want %v", schemaOperations, wantOperations)
	}

	types := []struct {
		definition string
		typeOf     reflect.Type
	}{
		{"configuration-consumer-input", reflect.TypeFor[ConfigurationConsumerInput]()},
		{"configuration-consumer", reflect.TypeFor[ConfigurationConsumer]()},
	}
	responseProperties := properties
	types = append(types,
		struct {
			definition string
			typeOf     reflect.Type
		}{"apply", reflect.TypeFor[ApplyResult]()},
		struct {
			definition string
			typeOf     reflect.Type
		}{"status", reflect.TypeFor[StatusResult]()},
		struct {
			definition string
			typeOf     reflect.Type
		}{"configuration", reflect.TypeFor[ConfigurationResult]()},
		struct {
			definition string
			typeOf     reflect.Type
		}{"configuration_change", reflect.TypeFor[ConfigurationChangeResult]()},
	)
	for _, test := range types {
		var definition map[string]any
		if strings.Contains(test.definition, "-") {
			definition = definitions[test.definition].(map[string]any)
		} else {
			definition = responseProperties[test.definition].(map[string]any)
		}
		got := sortedSchemaKeys(definition["properties"].(map[string]any))
		want := jsonFields(test.typeOf)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s schema fields = %v, Go fields = %v", test.definition, got, want)
		}
	}
}

func sortedSchemaKeys(properties map[string]any) []string {
	result := make([]string, 0, len(properties))
	for field := range properties {
		result = append(result, field)
	}
	sort.Strings(result)
	return result
}

func jsonFields(typeOf reflect.Type) []string {
	var result []string
	for index := 0; index < typeOf.NumField(); index++ {
		field := typeOf.Field(index)
		if field.Anonymous {
			result = append(result, jsonFields(field.Type)...)
			continue
		}
		name := strings.Split(field.Tag.Get("json"), ",")[0]
		if name != "" && name != "-" {
			result = append(result, name)
		}
	}
	sort.Strings(result)
	return result
}
