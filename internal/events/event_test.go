// ---
// relationships:
//   verifies: operational-events
// ---

package events

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestEventHasOnlyNormativeFields(t *testing.T) {
	typeOfEvent := reflect.TypeOf(Event{})
	want := []string{
		"Timestamp",
		"ConsumerID",
		"Operation",
		"Fingerprint",
		"Outcome",
		"Latency",
		"ErrorCode",
	}
	if typeOfEvent.NumField() != len(want) {
		t.Fatalf("Event field count = %d, want %d", typeOfEvent.NumField(), len(want))
	}
	for index, name := range want {
		field := typeOfEvent.Field(index)
		if field.Name != name {
			t.Errorf("Event field %d = %q, want %q", index, field.Name, name)
		}
		switch field.Type.Kind() {
		case reflect.Interface, reflect.Map, reflect.Slice:
			t.Errorf("Event.%s provides an open-ended %s escape hatch", field.Name, field.Type.Kind())
		}
	}

	forbidden := []string{
		"destination", "payload", "signature", "comment", "path",
		"raw", "message", "publickey", "error", "metadata", "attribute",
	}
	for index := range typeOfEvent.NumField() {
		name := strings.ToLower(typeOfEvent.Field(index).Name)
		for _, fragment := range forbidden {
			if strings.Contains(name, fragment) && name != "errorcode" {
				t.Errorf("Event field %q contains forbidden concept %q", name, fragment)
			}
		}
	}
}

func TestEventValidationClosesCategoricalVocabularies(t *testing.T) {
	valid := sampleEvent(1)
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid event: %v", err)
	}

	tests := map[string]func(*Event){
		"operation":  func(event *Event) { event.Operation = "other" },
		"outcome":    func(event *Event) { event.Outcome = "other" },
		"error-code": func(event *Event) { event.ErrorCode = "other" },
		"consumer-id": func(event *Event) {
			event.ConsumerID = "contains spaces"
		},
		"fingerprint": func(event *Event) {
			fingerprint := Fingerprint("not-a-fingerprint")
			event.Fingerprint = &fingerprint
		},
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
	first.ConsumerID = "subject-alpha"
	second := sampleEvent(2)
	second.ConsumerID = "subject-beta"
	second.Outcome = OutcomeDenied
	second.ErrorCode = ErrorPolicyDenied
	third := sampleEvent(3)
	third.ConsumerID = "subject-alpha"
	third.Outcome = OutcomeFailed
	third.ErrorCode = ErrorUpstreamTimeout
	for _, event := range []Event{first, second, third} {
		if err := store.Append(event); err != nil {
			t.Fatalf("Append(): %v", err)
		}
	}

	recent := store.Recent(2)
	if len(recent) != 2 || !recent[0].Timestamp.Equal(second.Timestamp) || !recent[1].Timestamp.Equal(third.Timestamp) {
		t.Fatalf("Recent(2) = %#v", recent)
	}
	activity := store.LastConsumerActivity()
	if got := activity["subject-alpha"]; !got.Equal(third.Timestamp) {
		t.Errorf("subject-alpha activity = %v, want %v", got, third.Timestamp)
	}
	if got := store.Health(); got.Category != HealthDegraded || got.ErrorCode != ErrorUpstreamTimeout {
		t.Errorf("Health() = %#v", got)
	}
	health := store.ConsumerHealth()
	if got := health["subject-beta"]; got.Category != HealthDenied || got.ErrorCode != ErrorPolicyDenied {
		t.Errorf("subject-beta health = %#v", got)
	}
}

func sampleEvent(sequence int) Event {
	return Event{
		Timestamp:  time.Date(2025, 2, 3, 4, 5, sequence, 0, time.UTC),
		ConsumerID: ConsumerID("subject-alpha"),
		Operation:  OperationListIdentities,
		Outcome:    OutcomeSucceeded,
		Latency:    time.Duration(sequence) * time.Millisecond,
		ErrorCode:  ErrorNone,
	}
}
