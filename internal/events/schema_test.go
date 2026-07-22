// ---
// relationships:
//   verifies: operational-events
// ---

package events

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestOperationalEventSchemaIsClosedAndMatchesDurableRecord(t *testing.T) {
	t.Parallel()

	schema := loadOperationalEventSchema(t)
	if schema["$schema"] != "https://json-schema.org/draft/2020-12/schema" {
		t.Fatalf("schema draft = %v", schema["$schema"])
	}
	if additional, ok := schema["additionalProperties"].(bool); !ok || additional {
		t.Fatalf("schema additionalProperties = %v, want false", schema["additionalProperties"])
	}
	properties := schema["properties"].(map[string]any)
	got := make([]string, 0, len(properties))
	for name := range properties {
		got = append(got, name)
	}
	sort.Strings(got)
	want := []string{
		"consumer-id",
		"error-code",
		"fingerprint",
		"latency",
		"operation",
		"outcome",
		"timestamp",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("schema properties = %v, want %v", got, want)
	}
	assertSchemaEnum(t, properties, "operation", []string{
		string(OperationConsumerConnect),
		string(OperationListIdentities),
		string(OperationSign),
		string(OperationSessionBind),
		string(OperationUpstreamConnect),
		string(OperationReplay),
		string(OperationReconcile),
	})
	assertSchemaEnum(t, properties, "outcome", []string{
		string(OutcomeSucceeded),
		string(OutcomeDenied),
		string(OutcomeFailed),
	})
	assertSchemaEnum(t, properties, "error-code", []string{
		string(ErrorNone),
		string(ErrorPolicyDenied),
		string(ErrorUpstreamUnavailable),
		string(ErrorUpstreamTimeout),
		string(ErrorUpstreamProtocol),
		string(ErrorConsumerProtocol),
		string(ErrorResourceLimit),
		string(ErrorInternal),
	})
	if got := properties["consumer-id"].(map[string]any)["pattern"]; got != consumerIDPattern.String() {
		t.Errorf("consumer-id pattern = %v, want %q", got, consumerIDPattern.String())
	}
	if got := properties["fingerprint"].(map[string]any)["pattern"]; got != fingerprintPattern.String() {
		t.Errorf("fingerprint pattern = %v, want %q", got, fingerprintPattern.String())
	}

	frame, err := encodeFrame(sampleEvent(1))
	if err != nil {
		t.Fatal(err)
	}
	var record map[string]any
	if err := json.Unmarshal(frame[frameHeaderBytes:], &record); err != nil {
		t.Fatal(err)
	}
	for key := range record {
		if _, exists := properties[key]; !exists {
			t.Errorf("durable record property %q is absent from schema", key)
		}
	}
}

func assertSchemaEnum(t *testing.T, properties map[string]any, property string, want []string) {
	t.Helper()
	raw := properties[property].(map[string]any)["enum"].([]any)
	got := make([]string, len(raw))
	for index, value := range raw {
		got[index] = value.(string)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%s enum = %v, want %v", property, got, want)
	}
}

func TestOperationalEventExclusionWordingMatchesAcrossAuthoritativeArtifacts(t *testing.T) {
	t.Parallel()

	want := "Events contain no signing payloads, signatures, public-key bytes, agent comments, filesystem paths, destinations, raw client messages, or raw upstream errors."
	paths := []string{
		filepath.Join("..", "..", "docs", "concepts", "wyrwood.yml"),
		filepath.Join("..", "..", "docs", "jobs", "use-host-ssh-keys-in-containers.yml"),
		filepath.Join("..", "..", "docs", "specifications", "operational-events.yml"),
		filepath.Join("..", "..", "docs", "technical-designs", "linux-per-user-agent-proxy.yml"),
	}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile(%s): %v", path, err)
		}
		normalized := strings.Join(strings.Fields(string(data)), " ")
		if !strings.Contains(normalized, want) {
			t.Errorf("%s does not contain the normative exclusion wording", path)
		}
	}
}

func loadOperationalEventSchema(t *testing.T) map[string]any {
	t.Helper()
	path := filepath.Join("..", "..", "docs", "specifications", "assets", "operational-events", "operational-event.schema.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(schema): %v", err)
	}
	var schema map[string]any
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatalf("operational-event schema is not valid JSON: %v", err)
	}
	return schema
}
