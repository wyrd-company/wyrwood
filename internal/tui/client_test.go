//go:build linux

// ---
// relationships:
//   verifies: terminal-interface
//   uses: control-interface
// ---

package tui

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/wyrd-company/wyrwood/internal/control"
)

type fakeContextControl struct {
	keys       control.KeysResult
	status     control.StatusResult
	events     control.EventsResult
	err        error
	eventLimit int
}

func (client *fakeContextControl) KeysContext(context.Context) (control.KeysResult, error) {
	return client.keys, client.err
}

func (client *fakeContextControl) StatusContext(context.Context) (control.StatusResult, error) {
	return client.status, client.err
}

func (client *fakeContextControl) EventsContext(_ context.Context, limit int) (control.EventsResult, error) {
	client.eventLimit = limit
	return client.events, client.err
}

func TestControlClientMapsDiagnosticProjections(t *testing.T) {
	timestamp := time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)
	controlClient := &fakeContextControl{
		keys: control.KeysResult{Keys: []control.Key{{Fingerprint: sampleFingerprint, Display: "sample"}}},
		status: control.StatusResult{
			Daemon: control.HealthHealthy, Upstream: control.HealthDegraded,
			Consumers: []control.ConsumerStatus{{ID: "unit", Name: "sample", Listener: control.HealthUnavailable, ActiveConnections: 3}},
			Truncated: true,
		},
		events: control.EventsResult{Events: []control.Event{{Timestamp: timestamp, ConsumerID: "unit", Operation: "sign", Outcome: "denied", ErrorCode: "policy-denied"}}},
	}
	client := NewControlClient(controlClient)
	keys, err := client.Keys(context.Background())
	if err != nil || !reflect.DeepEqual(keys, Keys{Keys: []Key{{Fingerprint: sampleFingerprint, Display: "sample"}}}) {
		t.Fatalf("keys = (%#v, %v)", keys, err)
	}
	status, err := client.Status(context.Background())
	wantStatus := Status{Daemon: HealthHealthy, Upstream: HealthDegraded, Consumers: []ConsumerStatus{{ID: "unit", Name: "sample", Listener: HealthUnavailable, ActiveConnections: 3}}, Truncated: true}
	if err != nil || !reflect.DeepEqual(status, wantStatus) {
		t.Fatalf("status = (%#v, %v), want %#v", status, err, wantStatus)
	}
	events, err := client.Events(context.Background(), 9)
	wantEvents := Events{Events: []Event{{Timestamp: timestamp, ConsumerID: "unit", Operation: "sign", Outcome: "denied", ErrorCode: "policy-denied"}}}
	if err != nil || !reflect.DeepEqual(events, wantEvents) || controlClient.eventLimit != 9 {
		t.Fatalf("events = (%#v, %v), limit %d", events, err, controlClient.eventLimit)
	}
	if _, err := client.Configuration(context.Background(), 0, 16, ""); !errors.Is(err, ErrConfigurationUnavailable) {
		t.Fatalf("configuration error = %v", err)
	}
}

func TestControlClientPreservesCategoricalFailures(t *testing.T) {
	want := &control.RemoteError{Code: control.ErrorUpstreamUnavailable}
	client := NewControlClient(&fakeContextControl{err: want})
	for _, request := range []func() error{
		func() error { _, err := client.Keys(context.Background()); return err },
		func() error { _, err := client.Status(context.Background()); return err },
		func() error { _, err := client.Events(context.Background(), 1); return err },
	} {
		if err := request(); !errors.Is(err, want) {
			t.Fatalf("adapter error = %v, want %v", err, want)
		}
	}
}
