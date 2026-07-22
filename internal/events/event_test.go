// ---
// relationships:
//   verifies: operational-events
// ---

package events

import (
	"fmt"
	"path/filepath"
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

func TestTimestampMustRoundTripThroughDurableRepresentation(t *testing.T) {
	t.Parallel()

	for _, year := range []int{-1, 10_000} {
		t.Run(fmt.Sprintf("year-%d", year), func(t *testing.T) {
			event := sampleEvent(1)
			event.Timestamp = time.Date(year, 1, 2, 3, 4, 5, 6, time.UTC)
			if err := event.Validate(); err == nil {
				t.Fatal("Validate() error = nil")
			}
			if _, err := encodeFrame(event); err == nil {
				t.Fatal("encodeFrame() error = nil")
			}
			store := openTestStore(t, 4)
			t.Cleanup(func() { _ = store.Close() })
			before, err := store.file.Stat()
			if err != nil {
				t.Fatal(err)
			}
			if err := store.Append(event); err == nil {
				t.Fatal("Append() error = nil")
			}
			after, err := store.file.Stat()
			if err != nil {
				t.Fatal(err)
			}
			if before.Size() != after.Size() {
				t.Errorf("rejected timestamp changed store size from %d to %d", before.Size(), after.Size())
			}
		})
	}
}

func TestValidTimestampBoundariesSurviveAppendAndRestart(t *testing.T) {
	for _, year := range []int{0, 9999} {
		t.Run(fmt.Sprintf("year-%04d", year), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state", "events.bin")
			store, err := Open(path, 4)
			if err != nil {
				t.Fatal(err)
			}
			event := sampleEvent(1)
			event.Timestamp = time.Date(year, 1, 2, 3, 4, 5, 6, time.FixedZone("fixture-zone", 3600))
			if err := store.Append(event); err != nil {
				t.Fatalf("Append(): %v", err)
			}
			normalized, err := normalizeTimestamp(event.Timestamp)
			if err != nil {
				t.Fatal(err)
			}
			before := store.Recent(1)[0].Timestamp
			if !reflect.DeepEqual(before, normalized) {
				t.Errorf("in-memory timestamp = %#v, want normalized %#v", before, normalized)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}

			reopened, err := Open(path, 4)
			if err != nil {
				t.Fatalf("Open(restart): %v", err)
			}
			t.Cleanup(func() { _ = reopened.Close() })
			after := reopened.Recent(1)[0].Timestamp
			if !reflect.DeepEqual(after, normalized) {
				t.Errorf("reopened timestamp = %#v, want normalized %#v", after, normalized)
			}
		})
	}
}

func TestAppendNormalizesTimestampBeforeQuery(t *testing.T) {
	store := openTestStore(t, 4)
	t.Cleanup(func() { _ = store.Close() })
	event := sampleEvent(1)
	event.Timestamp = time.Now()
	if err := store.Append(event); err != nil {
		t.Fatal(err)
	}
	want, err := normalizeTimestamp(event.Timestamp)
	if err != nil {
		t.Fatal(err)
	}
	got := store.Recent(1)[0].Timestamp
	if !reflect.DeepEqual(got, want) {
		t.Errorf("query timestamp = %#v, want canonical %#v", got, want)
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
	first.ConsumerID = ConsumerID(strings.Repeat("a", 64))
	second := sampleEvent(2)
	second.ConsumerID = ConsumerID(strings.Repeat("b", 64))
	second.Outcome = OutcomeDenied
	second.ErrorCode = ErrorPolicyDenied
	third := sampleEvent(3)
	third.ConsumerID = ConsumerID(strings.Repeat("a", 64))
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
	if got := activity[ConsumerID(strings.Repeat("a", 64))]; !got.Equal(third.Timestamp) {
		t.Errorf("subject-alpha activity = %v, want %v", got, third.Timestamp)
	}
	if got := store.Health(); got.Category != HealthDegraded || got.ErrorCode != ErrorUpstreamTimeout {
		t.Errorf("Health() = %#v", got)
	}
	health := store.ConsumerHealth()
	if got := health[ConsumerID(strings.Repeat("b", 64))]; got.Category != HealthDenied || got.ErrorCode != ErrorPolicyDenied {
		t.Errorf("subject-beta health = %#v", got)
	}
}

func sampleEvent(sequence int) Event {
	return Event{
		Timestamp:  time.Date(2025, 2, 3, 4, 5, sequence, 0, time.UTC),
		ConsumerID: ConsumerID(strings.Repeat("a", 64)),
		Operation:  OperationListIdentities,
		Outcome:    OutcomeSucceeded,
		Latency:    time.Duration(sequence) * time.Millisecond,
		ErrorCode:  ErrorNone,
	}
}
