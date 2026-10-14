// ---
// relationships:
//   verifies: operational-events
// ---

package events

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/wyrd-company/wyrwood/internal/schematest"
)

func TestEventHasOnlyClosedFields(t *testing.T) {
	typeOfEvent := reflect.TypeOf(Event{})
	for index := range typeOfEvent.NumField() {
		field := typeOfEvent.Field(index)
		switch field.Type.Kind() {
		case reflect.Interface, reflect.Map, reflect.Slice, reflect.Pointer, reflect.Struct:
			if field.Type != reflect.TypeOf(time.Time{}) {
				t.Errorf("Event.%s provides an open-ended %s escape hatch", field.Name, field.Type.Kind())
			}
		}
		name := strings.ToLower(field.Name)
		for _, fragment := range []string{"payload", "signature", "path", "raw", "message", "token", "secret", "body", "value", "metadata"} {
			if strings.Contains(name, fragment) {
				t.Errorf("Event field %q contains forbidden concept %q", name, fragment)
			}
		}
	}
}

func TestRecordMatchesSchemaPropertiesAndEnums(t *testing.T) {
	schema := schematest.Load(t, schematest.OperationalEvent)
	properties := schema["properties"].(map[string]any)
	got := jsonFieldNames(reflect.TypeOf(Record{}))
	want := make([]string, 0, len(properties))
	for name := range properties {
		want = append(want, name)
	}
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("record fields = %v, schema properties = %v", got, want)
	}
	assertEnum(t, properties, "operation", Operations)
	assertEnum(t, properties, "outcome", Outcomes)
	assertEnum(t, properties, "error", ErrorCodes)
	assertEnum(t, properties, "mount", Mounts)
	assertEnum(t, properties, "method", Methods)
}

func TestEveryValidRecordValidatesAgainstSchema(t *testing.T) {
	schema := schematest.Compile(t, schematest.OperationalEvent)
	fingerprint := "SHA256:" + strings.Repeat("A", 43)
	samples := []Event{
		sampleEvent(1),
		{
			Time: time.Date(2026, 1, 2, 3, 4, 5, 6, time.UTC), Operation: OperationVaultRequest,
			Outcome: OutcomeDenied, ErrorCode: ErrorOpenBaoDenied, Latency: time.Millisecond,
			Binding: "b-0123456789abcdef", ContainerKey: ContainerKey("name", "web"),
			Mount: MountKV, Method: MethodGet,
		},
		{
			Time: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), Operation: OperationSSHSign,
			Outcome: OutcomeOK, Fingerprint: fingerprint, Binding: "b-1",
			ContainerKey: ContainerKey("devcontainer", "/home/user/project"),
		},
		{
			Time: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), Operation: OperationBindingCreated,
			Outcome: OutcomeOK, Agent: "host.example", Policy: "teal", Operator: "subject-1",
		},
	}
	for _, operation := range Operations {
		event := sampleEvent(2)
		event.Operation = operation
		samples = append(samples, event)
	}
	for _, code := range ErrorCodes {
		event := sampleEvent(3)
		event.Outcome = OutcomeFailed
		event.ErrorCode = code
		samples = append(samples, event)
	}
	for _, event := range samples {
		data, err := json.Marshal(event.Record())
		if err != nil {
			t.Fatal(err)
		}
		if err := schematest.Validate(schema, data); err != nil {
			t.Errorf("%s does not validate: %v", data, err)
		}
		decoded, err := decodeFrame(data)
		if err != nil {
			t.Errorf("decodeFrame(%s) = %v", data, err)
		}
		if decoded != event {
			t.Errorf("round trip = %#v, want %#v", decoded, event)
		}
	}
}

func TestDevcontainerKeyNeverRecordsPath(t *testing.T) {
	key := ContainerKey("devcontainer", "/home/user/secret-project")
	if strings.Contains(key, "/") || strings.Contains(key, "secret") {
		t.Fatalf("ContainerKey() = %q leaks the path", key)
	}
	if key != ContainerKey("devcontainer", "/home/user/secret-project") {
		t.Fatal("ContainerKey() is not stable")
	}
	if got := ContainerKey("name", "web"); got != "name:web" {
		t.Fatalf("ContainerKey(name) = %q", got)
	}
	event := sampleEvent(1)
	event.ContainerKey = "devcontainer:/home/user"
	if err := event.Validate(); err == nil {
		t.Fatal("Validate() accepted a path-bearing container key")
	}
}

func TestTimestampMustRoundTripThroughDurableRepresentation(t *testing.T) {
	for _, year := range []int{-1, 10_000} {
		t.Run(fmt.Sprintf("year-%d", year), func(t *testing.T) {
			event := sampleEvent(1)
			event.Time = time.Date(year, 1, 1, 0, 0, 0, 0, time.UTC)
			if err := event.Validate(); err == nil {
				t.Fatal("Validate() error = nil")
			}
		})
	}
}

func TestEventValidationClosesCategoricalVocabularies(t *testing.T) {
	valid := sampleEvent(1)
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid event: %v", err)
	}
	tests := map[string]func(*Event){
		"operation":       func(event *Event) { event.Operation = "other" },
		"outcome":         func(event *Event) { event.Outcome = "other" },
		"error":           func(event *Event) { event.Outcome = OutcomeFailed; event.ErrorCode = "other" },
		"ok-with-error":   func(event *Event) { event.ErrorCode = ErrorInternal },
		"failed-no-error": func(event *Event) { event.Outcome = OutcomeFailed },
		"binding":         func(event *Event) { event.Binding = "Contains Spaces" },
		"fingerprint":     func(event *Event) { event.Fingerprint = "not-a-fingerprint" },
		"mount":           func(event *Event) { event.Mount = "secret" },
		"method":          func(event *Event) { event.Method = "PATCH" },
		"latency":         func(event *Event) { event.Latency = -1 },
		"control":         func(event *Event) { event.Agent = "host\nname" },
		"policy":          func(event *Event) { event.Policy = strings.Repeat("p", 65) },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			event := valid
			mutate(&event)
			if err := event.Validate(); err == nil {
				t.Fatal("Validate() error = nil")
			}
		})
	}
}

func TestProjectionQueriesUseRetainedEvents(t *testing.T) {
	store := openTestStore(t, 8)
	t.Cleanup(func() { _ = store.Close() })

	first := sampleEvent(1)
	first.Binding = "b-a"
	second := sampleEvent(2)
	second.Binding = "b-b"
	second.Outcome = OutcomeDenied
	second.ErrorCode = ErrorOpenBaoDenied
	third := sampleEvent(3)
	third.Binding = "b-a"
	third.Outcome = OutcomeTimeout
	third.ErrorCode = ErrorOpenBaoTimeout
	for _, event := range []Event{first, second, third} {
		if err := store.Append(event); err != nil {
			t.Fatalf("Append(): %v", err)
		}
	}
	recent := store.Recent(2)
	if len(recent) != 2 || recent[0] != second || recent[1] != third {
		t.Fatalf("Recent(2) = %#v", recent)
	}
	health := store.BindingHealth()
	if health["b-a"] != HealthDegraded || health["b-b"] != HealthDenied || len(health) != 2 {
		t.Fatalf("BindingHealth() = %#v", health)
	}
}

func sampleEvent(sequence int) Event {
	return Event{
		Time:      time.Date(2025, 2, 3, 4, 5, sequence, 0, time.UTC),
		Operation: OperationSSHList,
		Outcome:   OutcomeOK,
		Latency:   time.Duration(sequence) * time.Millisecond,
	}
}

func jsonFieldNames(value reflect.Type) []string {
	names := make([]string, 0, value.NumField())
	for index := range value.NumField() {
		names = append(names, strings.Split(value.Field(index).Tag.Get("json"), ",")[0])
	}
	sort.Strings(names)
	return names
}

func assertEnum[T ~string](t *testing.T, properties map[string]any, property string, values []T) {
	t.Helper()
	raw := properties[property].(map[string]any)["enum"].([]any)
	got := make([]string, 0, len(raw))
	for _, item := range raw {
		got = append(got, item.(string))
	}
	want := make([]string, 0, len(values))
	for _, value := range values {
		want = append(want, string(value))
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%s enum = %v, Go vocabulary = %v", property, got, want)
	}
}
