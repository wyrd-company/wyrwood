// ---
// relationships:
//   verifies:
//     - controller
//     - agent-controller-protocol
// ---

package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/wyrd-company/wyrwood/internal/controller/store"
	"github.com/wyrd-company/wyrwood/internal/protocol"
)

var (
	statusContainer = strings.Repeat("a", 64)
	otherContainer  = strings.Repeat("b", 64)
)

type readinessFixture struct {
	valueFixture
	binding store.Binding
	marker  *int
}

func newReadinessFixture(t *testing.T) readinessFixture {
	t.Helper()
	fixture := newValueFixture(t)
	binding, err := fixture.h.controller.CreateBinding(context.Background(), "host-a", fixture.key, valueSelection(map[string]string{"slug": "alpha"}), "operator-1")
	if err != nil {
		t.Fatalf("CreateBinding() = %v", err)
	}
	return readinessFixture{valueFixture: fixture, binding: binding, marker: new(int)}
}

// report sends messages and an inventory, and waits until the session has
// handled each one. A policy set is no such signal: other changes also push one.
func (fixture readinessFixture) report(t *testing.T, containers []protocol.Container, messages ...protocol.Message) BindingStatus {
	t.Helper()
	ctx := context.Background()
	data := fixture.h.controller.Store()
	// A marker no inventory holds otherwise proves that this inventory arrived,
	// also when it repeats the last one.
	*fixture.marker++
	marker := protocol.Container{ID: fmt.Sprintf("%064x", *fixture.marker), Name: "marker", State: protocol.StateExited, Keys: []protocol.Key{{Kind: protocol.KeyName, Value: "marker"}}}
	for _, message := range append(messages, protocol.Inventory{Containers: append(slices.Clone(containers), marker)}) {
		if err := fixture.connection.conn.Send(message); err != nil {
			t.Fatal(err)
		}
	}
	eventually(t, func() bool {
		stored, _, err := data.Inventory(ctx, "host-a")
		return err == nil && slices.ContainsFunc(stored, func(container protocol.Container) bool { return container.ID == marker.ID })
	})
	status, err := fixture.h.controller.BindingStatus(ctx, fixture.binding.ID)
	if err != nil {
		t.Fatalf("BindingStatus() = %v", err)
	}
	return status
}

func (fixture readinessFixture) container(state protocol.State) []protocol.Container {
	return []protocol.Container{{ID: statusContainer, Name: "web", Image: "busybox", State: state, Keys: []protocol.Key{fixture.key}}}
}

func (fixture readinessFixture) ready() protocol.BindingStatus {
	return protocol.BindingStatus{Binding: fixture.binding.ID, Assignment: fixture.binding.Assignment(), Token: protocol.TokenValid, Outcome: protocol.OutcomeConforming,
		Consumers: []protocol.ConsumerStatus{{Directory: "/run/wyrwood/containers/web", ContainerID: statusContainer, Sockets: append([]protocol.Socket(nil), protocol.Sockets...)}}}
}

func assertReadiness(t *testing.T, status BindingStatus, readiness Readiness, reasons ...NotReadyReason) {
	t.Helper()
	if status.Readiness != readiness || !slices.Equal(status.Reasons, reasons) {
		t.Fatalf("readiness = %q %v, want %q %v", status.Readiness, status.Reasons, readiness, reasons)
	}
}

func TestReadyIsEveryPartTogetherAndHoldsForACreatedContainer(t *testing.T) {
	fixture := newReadinessFixture(t)
	status := fixture.report(t, fixture.container(protocol.StateCreated), fixture.ready())
	assertReadiness(t, status, ReadinessReady)
	if len(status.Containers) != 1 || status.Containers[0].ID != statusContainer || status.Containers[0].State != protocol.StateCreated {
		t.Fatalf("containers = %#v", status.Containers)
	}
	if !status.AgentConnected || status.Token != protocol.TokenValid || status.Outcome != protocol.OutcomeConforming || status.Consumers[0].Directory == "" {
		t.Fatalf("status = %#v", status)
	}
	status = fixture.report(t, fixture.container(protocol.StateExited), fixture.ready())
	assertReadiness(t, status, ReadinessReady)
}

func TestEachMissingPartKeepsTheBindingFromReady(t *testing.T) {
	fixture := newReadinessFixture(t)
	for _, test := range []struct {
		name      string
		change    func(*protocol.BindingStatus)
		readiness Readiness
		reason    NotReadyReason
	}{
		{"another assignment", func(status *protocol.BindingStatus) { status.Assignment = "old-assignment" }, ReadinessWaiting, ReasonAgentReport},
		{"a rebuilt container's old report", func(status *protocol.BindingStatus) { status.Consumers[0].ContainerID = otherContainer }, ReadinessWaiting, ReasonAgentReport},
		{"no consumer", func(status *protocol.BindingStatus) { status.Consumers = nil }, ReadinessWaiting, ReasonAgentReport},
		{"a socket missing", func(status *protocol.BindingStatus) { status.Consumers[0].Sockets = status.Consumers[0].Sockets[:1] }, ReadinessWaiting, ReasonSockets},
		{"no token", func(status *protocol.BindingStatus) { status.Token = protocol.TokenNone }, ReadinessWaiting, ReasonToken},
		{"an expired token", func(status *protocol.BindingStatus) { status.Token = protocol.TokenExpired }, ReadinessWaiting, ReasonToken},
		{"no result", func(status *protocol.BindingStatus) { status.Outcome = "" }, ReadinessWaiting, ReasonConformance},
		{"recreating", func(status *protocol.BindingStatus) { status.Outcome = protocol.OutcomeRecreating }, ReadinessWaiting, ReasonConformance},
		{"non-conforming", func(status *protocol.BindingStatus) { status.Outcome = protocol.OutcomeNonConforming }, ReadinessFailed, ReasonConformance},
		{"recreate failed", func(status *protocol.BindingStatus) { status.Outcome = protocol.OutcomeRecreateFailed }, ReadinessFailed, ReasonConformance},
		{"directory failure", func(status *protocol.BindingStatus) {
			status.Consumers[0].Failed, status.Consumers[0].Sockets = protocol.FailedConsumerDirectory, nil
		}, ReadinessFailed, ReasonConsumerDirectory},
		{"group failure", func(status *protocol.BindingStatus) { status.Consumers[0].Failed = protocol.FailedAccessGroup }, ReadinessFailed, ReasonAccessGroup},
	} {
		t.Run(test.name, func(t *testing.T) {
			report := fixture.ready()
			test.change(&report)
			status := fixture.report(t, fixture.container(protocol.StateRunning), report)
			if status.Readiness != test.readiness || !slices.Contains(status.Reasons, test.reason) {
				t.Fatalf("readiness = %q %v, want %q with %q", status.Readiness, status.Reasons, test.readiness, test.reason)
			}
		})
	}
}

func TestFailureIsListedAheadOfWhatStillWaits(t *testing.T) {
	fixture := newReadinessFixture(t)
	report := fixture.ready()
	report.Token, report.Outcome = protocol.TokenNone, protocol.OutcomeNonConforming
	report.FailedItems = []protocol.FailedItem{protocol.FailedMount}
	report.LastError = protocol.CredentialDenied
	status := fixture.report(t, fixture.container(protocol.StateRunning), report)
	assertReadiness(t, status, ReadinessFailed, ReasonConformance, ReasonToken)
	if !slices.Equal(status.FailedItems, report.FailedItems) || status.LastError != protocol.CredentialDenied {
		t.Fatalf("status = %#v", status)
	}
}

// The stored contract result outlives its container; readiness does not read it.
func TestStoredResultNeverMakesARemovedContainerReady(t *testing.T) {
	fixture := newReadinessFixture(t)
	status := fixture.report(t, fixture.container(protocol.StateRunning),
		protocol.ContractResult{Binding: fixture.binding.ID, Outcome: protocol.OutcomeConforming})
	assertReadiness(t, status, ReadinessWaiting, ReasonAgentReport)
	if status.Outcome != "" {
		t.Fatalf("outcome read from the store: %#v", status)
	}

	assertReadiness(t, fixture.report(t, fixture.container(protocol.StateRunning), fixture.ready()), ReadinessReady)
	prepared := fixture.ready()
	prepared.Consumers[0].ContainerID, prepared.Outcome, prepared.Token = "", "", protocol.TokenNone
	status = fixture.report(t, nil, prepared)
	assertReadiness(t, status, ReadinessWaiting, ReasonNoContainer)
	if len(status.Containers) != 0 || status.Consumers[0].Directory == "" || len(status.Consumers[0].Sockets) != 2 {
		t.Fatalf("prepared = %#v", status)
	}
	if stored, err := fixture.h.controller.Store().ContractResults(context.Background()); err != nil || stored[fixture.binding.ID].Outcome != protocol.OutcomeConforming {
		t.Fatalf("stored results = %#v, %v", stored, err)
	}
}

func TestPreparedDirectoryFailureIsFailedWithNoContainer(t *testing.T) {
	fixture := newReadinessFixture(t)
	report := protocol.BindingStatus{Binding: fixture.binding.ID, Assignment: fixture.binding.Assignment(), Token: protocol.TokenNone,
		Consumers: []protocol.ConsumerStatus{{Directory: "/run/wyrwood/containers/web", Failed: protocol.FailedConsumerDirectory}}}
	assertReadiness(t, fixture.report(t, nil, report), ReadinessFailed, ReasonConsumerDirectory, ReasonNoContainer)
}

func TestOtherKeyWithNoContainerWaitsForIt(t *testing.T) {
	fixture := newReadinessFixture(t)
	key := protocol.Key{Kind: protocol.KeyCompose, Value: "sample/worker"}
	binding, err := fixture.h.controller.CreateBinding(context.Background(), "host-a", key, valueSelection(map[string]string{"slug": "beta"}), "operator-1")
	if err != nil {
		t.Fatal(err)
	}
	status, err := fixture.h.controller.BindingStatus(context.Background(), binding.ID)
	if err != nil {
		t.Fatal(err)
	}
	assertReadiness(t, status, ReadinessWaiting, ReasonNoContainer)
}

// A binding with several containers is ready only when each has its consumer.
func TestEveryContainerOfABindingMustBeReady(t *testing.T) {
	fixture := newReadinessFixture(t)
	key := protocol.Key{Kind: protocol.KeyCompose, Value: "sample/worker"}
	binding, err := fixture.h.controller.CreateBinding(context.Background(), "host-a", key, valueSelection(map[string]string{"slug": "beta"}), "operator-1")
	if err != nil {
		t.Fatal(err)
	}
	sockets := append([]protocol.Socket(nil), protocol.Sockets...)
	containers := []protocol.Container{
		{ID: statusContainer, Name: "worker-1", State: protocol.StateRunning, Keys: []protocol.Key{key}},
		{ID: otherContainer, Name: "worker-2", State: protocol.StateRunning, Keys: []protocol.Key{key}},
	}
	report := protocol.BindingStatus{Binding: binding.ID, Assignment: binding.Assignment(), Token: protocol.TokenValid, Outcome: protocol.OutcomeConforming,
		Consumers: []protocol.ConsumerStatus{{Directory: "/run/1", ContainerID: statusContainer, Sockets: sockets}}}
	fixture.binding = binding
	assertReadiness(t, fixture.report(t, containers, report), ReadinessWaiting, ReasonAgentReport)
	report.Consumers = append(report.Consumers, protocol.ConsumerStatus{Directory: "/run/2", ContainerID: otherContainer, Sockets: sockets})
	assertReadiness(t, fixture.report(t, containers, report), ReadinessReady)
}

func TestDisconnectEndsWhatTheAgentReported(t *testing.T) {
	fixture := newReadinessFixture(t)
	assertReadiness(t, fixture.report(t, fixture.container(protocol.StateRunning), fixture.ready()), ReadinessReady)
	_ = fixture.connection.client.Close()
	eventually(t, func() bool { return !fixture.h.controller.Connected("host-a") })
	status, err := fixture.h.controller.BindingStatus(context.Background(), fixture.binding.ID)
	if err != nil {
		t.Fatal(err)
	}
	assertReadiness(t, status, ReadinessUnknown, ReasonAgentDisconnected)
	if status.AgentConnected || status.Token != "" || status.Outcome != "" || len(status.Consumers) != 0 {
		t.Fatalf("status after disconnect = %#v", status)
	}
	if len(status.Containers) != 1 || status.LastReport.IsZero() {
		t.Fatalf("last report not kept: %#v", status)
	}
}

func TestStatusOfAnotherAgentsBindingIsDropped(t *testing.T) {
	fixture := newReadinessFixture(t)
	ctx := context.Background()
	otherKey := newAgentKey(t)
	_, _ = fixture.h.dial("host-b", otherKey)
	if err := fixture.h.controller.DecideAgent(ctx, gossh.FingerprintSHA256(otherKey.PublicKey()), true, "operator-1"); err != nil {
		t.Fatal(err)
	}
	other, err := fixture.h.dial("host-b", otherKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = other.client.Close() })
	for _, message := range []protocol.Message{protocol.Hello{AgentVersion: "test"}, fixture.ready(),
		protocol.BindingStatus{Binding: "absent-binding", Assignment: "assignment", Token: protocol.TokenNone}, protocol.Inventory{Containers: []protocol.Container{}}} {
		if err := other.conn.Send(message); err != nil {
			t.Fatal(err)
		}
	}
	if _, ok := other.receive(t).(protocol.PolicySet); !ok {
		t.Fatal("no policy set for the other agent")
	}
	session := fixture.h.controller.hub.session("host-b")
	if session == nil {
		t.Fatal("no session")
	}
	session.mu.Lock()
	held := len(session.statuses)
	session.mu.Unlock()
	if held != 0 {
		t.Fatalf("statuses held for bindings the agent does not own = %d", held)
	}
}

func TestBindingStatusesListsEveryBindingOfTheAgent(t *testing.T) {
	fixture := newReadinessFixture(t)
	fixture.report(t, fixture.container(protocol.StateRunning), fixture.ready())
	key := protocol.Key{Kind: protocol.KeyCompose, Value: "sample/worker"}
	second, err := fixture.h.controller.CreateBinding(context.Background(), "host-a", key, valueSelection(map[string]string{"slug": "beta"}), "operator-1")
	if err != nil {
		t.Fatal(err)
	}
	statuses, err := fixture.h.controller.BindingStatuses(context.Background(), "host-a")
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]BindingStatus{}
	for _, status := range statuses {
		byID[status.Binding] = status
	}
	if len(byID) != 2 || byID[fixture.binding.ID].Readiness != ReadinessReady || byID[second.ID].Readiness != ReadinessWaiting {
		t.Fatalf("statuses = %#v", statuses)
	}
}

func TestBindingStatusOfAnUnknownBindingIsNotFound(t *testing.T) {
	fixture := newReadinessFixture(t)
	if _, err := fixture.h.controller.BindingStatus(context.Background(), "absent-binding"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("BindingStatus() = %v", err)
	}
}

func TestBindingStatusIsMachineReadableAndHoldsNoSecret(t *testing.T) {
	fixture := newReadinessFixture(t)
	status := fixture.report(t, fixture.container(protocol.StateRunning), fixture.ready())
	data, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"binding", "agent", "key", "agent-connected", "last-report", "readiness", "containers", "consumers", "token", "outcome"} {
		if _, ok := decoded[field]; !ok {
			t.Fatalf("field %q missing from %s", field, data)
		}
	}
	if decoded["token"] != "valid" || decoded["readiness"] != "ready" {
		t.Fatalf("status = %s", data)
	}
	for _, secret := range []string{"secret-id", "wrapped", "role-id", "accessor", "hvs."} {
		if strings.Contains(string(data), secret) {
			t.Fatalf("status holds %q: %s", secret, data)
		}
	}
}

func eventually(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
