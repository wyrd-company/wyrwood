// ---
// relationships:
//   verifies: command-line-interface
// ---

package command

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"testing"
	"time"

	"github.com/wyrd-company/wyrwood/internal/control"
	"github.com/wyrd-company/wyrwood/internal/userservice"
)

func TestCommandOutputSchemaIsClosedAndVersioned(t *testing.T) {
	schema := loadCommandSchema(t)
	if schema["$schema"] != "https://json-schema.org/draft/2020-12/schema" {
		t.Fatalf("schema draft = %v", schema["$schema"])
	}
	if schema["additionalProperties"] != false {
		t.Fatal("command envelope schema is not closed")
	}
	properties := object(t, schema["properties"])
	version := object(t, properties["version"])
	if version["const"] != float64(1) {
		t.Fatalf("schema version = %v", version["const"])
	}
	variants := array(t, schema["oneOf"])
	if len(variants) != 10 {
		t.Fatalf("schema variants = %d, want 10", len(variants))
	}
	successes := []struct {
		commands []string
		result   string
	}{
		{[]string{"init"}, "init-result"}, {[]string{"apply"}, "apply-result"},
		{[]string{"keys"}, "keys-result"}, {[]string{"status"}, "status-result"},
		{[]string{"events"}, "events-result"}, {[]string{"configuration-show"}, "configuration-result"},
		{[]string{"configuration-set-upstream", "configuration-set-timeouts"}, "configuration-change-result"},
		{[]string{"consumer-put", "consumer-retire"}, "consumer-change-result"}, {[]string{"service"}, "service-result"},
	}
	for index, success := range successes {
		variant := object(t, variants[index])
		variantProperties := object(t, variant["properties"])
		commandSchema := object(t, variantProperties["command"])
		var commands []string
		if constant, ok := commandSchema["const"].(string); ok {
			commands = []string{constant}
		} else {
			for _, value := range array(t, commandSchema["enum"]) {
				commands = append(commands, value.(string))
			}
		}
		if !reflect.DeepEqual(commands, success.commands) || object(t, variantProperties["result"])["$ref"] != "#/$defs/"+success.result {
			t.Fatalf("schema variant %d = %v -> %v, want %v -> %s", index, commands, object(t, variantProperties["result"])["$ref"], success.commands, success.result)
		}
		if !reflect.DeepEqual(array(t, object(t, variant["not"])["required"]), []any{"error"}) {
			t.Fatalf("schema success variant %v permits an error", commands)
		}
	}
	errorVariant := object(t, variants[9])
	if !reflect.DeepEqual(array(t, object(t, errorVariant["not"])["required"]), []any{"result"}) {
		t.Fatal("schema error variant permits a result")
	}
	definitions := object(t, schema["$defs"])
	for _, name := range []string{"init-result", "apply-result", "key", "keys-result", "consumer-status", "status-result", "event", "events-result", "configuration-consumer", "configuration-result", "configuration-change-result", "consumer-change-result", "service-result", "error-result"} {
		if object(t, definitions[name])["additionalProperties"] != false {
			t.Fatalf("schema definition %s is not closed", name)
		}
	}
}

func TestCommandSchemaCarriesControlBoundsAndDeadline(t *testing.T) {
	schema := loadCommandSchema(t)
	definitions := object(t, schema["$defs"])
	apply := object(t, object(t, definitions["apply-result"])["properties"])
	if object(t, apply["committed"])["const"] != true {
		t.Fatal("structured CLI success permits an uncommitted apply")
	}
	keys := object(t, object(t, object(t, definitions["keys-result"])["properties"])["keys"])
	if keys["maxItems"] != float64(control.MaximumProjectedKeys) {
		t.Fatalf("key maximum = %v", keys["maxItems"])
	}
	consumers := object(t, object(t, object(t, definitions["status-result"])["properties"])["consumers"])
	if consumers["maxItems"] != float64(control.MaximumProjectedConsumers) {
		t.Fatalf("consumer maximum = %v", consumers["maxItems"])
	}
	events := object(t, object(t, object(t, definitions["events-result"])["properties"])["events"])
	if events["maxItems"] != float64(control.MaximumEventLimit) {
		t.Fatalf("event maximum = %v", events["maxItems"])
	}
	if defaultEventLimit < 1 || defaultEventLimit > control.MaximumEventLimit {
		t.Fatalf("default event limit = %d", defaultEventLimit)
	}
	if control.ClientOperationTimeout != 65*time.Second || control.ClientOperationTimeout <= 0 {
		t.Fatalf("client operation timeout = %s", control.ClientOperationTimeout)
	}
}

func TestServiceSchemaRejectsContradictoryInstallationState(t *testing.T) {
	definitions := object(t, loadCommandSchema(t)["$defs"])
	service := object(t, definitions["service-result"])
	variants := array(t, service["oneOf"])
	if len(variants) != 2 {
		t.Fatalf("service state variants = %d", len(variants))
	}
	absent := object(t, object(t, variants[0])["properties"])
	if object(t, absent["installed"])["const"] != false ||
		object(t, absent["enabled"])["const"] != false ||
		object(t, absent["state"])["const"] != "not-installed" {
		t.Fatal("absent service state is not closed")
	}
	installed := object(t, object(t, variants[1])["properties"])
	if object(t, installed["installed"])["const"] != true ||
		!reflect.DeepEqual(array(t, object(t, installed["state"])["enum"]), []any{"inactive", "active", "failed"}) {
		t.Fatal("installed service state is not closed")
	}
}

func TestStructuredTypesAndSchemaExposeTheSameFields(t *testing.T) {
	schema := loadCommandSchema(t)
	definitions := object(t, schema["$defs"])
	tests := []struct {
		definition string
		typeOf     reflect.Type
	}{
		{definition: "init-result", typeOf: reflect.TypeFor[initResult]()},
		{definition: "apply-result", typeOf: reflect.TypeFor[control.ApplyResult]()},
		{definition: "key", typeOf: reflect.TypeFor[control.Key]()},
		{definition: "keys-result", typeOf: reflect.TypeFor[control.KeysResult]()},
		{definition: "consumer-status", typeOf: reflect.TypeFor[control.ConsumerStatus]()},
		{definition: "status-result", typeOf: reflect.TypeFor[control.StatusResult]()},
		{definition: "event", typeOf: reflect.TypeFor[control.Event]()},
		{definition: "events-result", typeOf: reflect.TypeFor[control.EventsResult]()},
		{definition: "service-result", typeOf: reflect.TypeFor[userservice.Result]()},
		{definition: "error-result", typeOf: reflect.TypeFor[errorProjection]()},
	}
	for _, test := range tests {
		t.Run(test.definition, func(t *testing.T) {
			definition := object(t, definitions[test.definition])
			properties := sortedKeys(object(t, definition["properties"]))
			fields := jsonFieldNames(test.typeOf)
			if !reflect.DeepEqual(properties, fields) {
				t.Fatalf("schema fields = %v, Go fields = %v", properties, fields)
			}
		})
	}
}

func TestCommandErrorSchemaContainsEveryEmittedCategory(t *testing.T) {
	schema := loadCommandSchema(t)
	definitions := object(t, schema["$defs"])
	errorDefinition := object(t, definitions["error-result"])
	properties := object(t, errorDefinition["properties"])
	codes := array(t, object(t, properties["code"])["enum"])
	actual := make([]string, len(codes))
	for index, code := range codes {
		actual[index] = code.(string)
	}
	sort.Strings(actual)
	want := []string{
		"apply-failed", "apply-invalid", "daemon-failed", "daemon-unavailable",
		"configuration-conflict", "configuration-durability-uncertain", "configuration-failed", "configuration-invalid", "configuration-not-found",
		"durability-uncertain", "incompatible-daemon", "initialization-failed",
		"request-rejected", "resource-limit", "upstream-unavailable", "usage",
		"service-failed", "service-not-installed", "service-unavailable",
	}
	sort.Strings(want)
	if !reflect.DeepEqual(actual, want) {
		t.Fatalf("schema error codes = %v, want %v", actual, want)
	}
}

func loadCommandSchema(t *testing.T) map[string]any {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source")
	}
	path := filepath.Join(filepath.Dir(source), "..", "..", "docs", "specifications", "assets", "command-line-interface", "command-output.schema.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(schema): %v", err)
	}
	var schema map[string]any
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatalf("command schema is not valid JSON: %v", err)
	}
	return schema
}

func object(t *testing.T, value any) map[string]any {
	t.Helper()
	object, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("schema value %#v is not an object", value)
	}
	return object
}

func array(t *testing.T, value any) []any {
	t.Helper()
	array, ok := value.([]any)
	if !ok {
		t.Fatalf("schema value %#v is not an array", value)
	}
	return array
}

func sortedKeys(values map[string]any) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func jsonFieldNames(value reflect.Type) []string {
	fields := make([]string, 0, value.NumField())
	for index := 0; index < value.NumField(); index++ {
		name := value.Field(index).Tag.Get("json")
		for position, character := range name {
			if character == ',' {
				name = name[:position]
				break
			}
		}
		fields = append(fields, name)
	}
	sort.Strings(fields)
	return fields
}
