// ---
// relationships:
//   verifies:
//     - agent
//     - container-contract
// ---

package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wyrd-company/wyrwood/internal/config"
	"github.com/wyrd-company/wyrwood/internal/engine"
	"github.com/wyrd-company/wyrwood/internal/engine/enginetest"
	"github.com/wyrd-company/wyrwood/internal/policy"
	"github.com/wyrd-company/wyrwood/internal/protocol"
)

// newRecreateAgent returns an agent that may recreate, without starting it.
func newRecreateAgent(t *testing.T, fake engine.Engine) *Agent {
	t.Helper()
	return newRecreateAgentAt(t, fake, newPaths(t))
}

// newRecreateAgentAt is newRecreateAgent over existing state.
func newRecreateAgentAt(t *testing.T, fake engine.Engine, paths Paths) *Agent {
	t.Helper()
	if err := os.MkdirAll(paths.State, 0o700); err != nil {
		t.Fatal(err)
	}
	configuration := config.Agent{ConsumerRoot: filepath.Join(paths.Runtime, "containers"), AllowRecreate: true,
		EngineTimeout: 5 * time.Second, OpenBaoTimeout: 5 * time.Second}
	instance, err := New(Options{Config: configuration, Paths: paths, Engine: fake, Endpoints: probeEndpoints{},
		Hostname: "host-a", CanAssign: func(uint32) bool { return true }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(instance.shutdown)
	return instance
}

func recreateBinding() protocol.Binding {
	document := policy.New("recreate", `path "kv/data/app/*" { capabilities = ["read"] }`)
	document.Contract.Enforcement = policy.EnforcementRecreate
	return protocol.Binding{Binding: "bnd-1", Key: protocol.Key{Kind: protocol.KeyName, Value: "app"}, Policy: document}
}

func runningApp(fake *enginetest.Fake) engine.Container {
	app := engine.Container{Name: "/app"}
	app.State.Status = "running"
	fake.Add(app)
	added, _ := fake.ByName("app")
	return added
}

// journalAtStop fails the test unless a recreate journal exists when the
// engine is asked to stop a container. List fails, so the reconcile that
// follows a recreate cannot clear the journal on the recreate's behalf.
type journalAtStop struct {
	*enginetest.Fake
	t       *testing.T
	journal string
}

func (wrapped journalAtStop) Stop(ctx context.Context, id string, timeout time.Duration) error {
	if _, err := os.Stat(wrapped.journal); err != nil {
		wrapped.t.Errorf("recreate journal absent at stop: %v", err)
	}
	return wrapped.Fake.Stop(ctx, id, timeout)
}

func (journalAtStop) List(context.Context) ([]engine.Summary, error) {
	return nil, engine.ErrUnavailable
}

func TestRecreateJournalSpansTheRecreate(t *testing.T) {
	fake := enginetest.New()
	app := runningApp(fake)
	wrapped := &journalAtStop{Fake: fake, t: t}
	instance := newRecreateAgent(t, wrapped)
	wrapped.journal = instance.paths.RecreateJournal("app")
	instance.recreate(context.Background(), recreateBinding(), app)
	if calls := strings.Join(fake.CallLog(), ","); calls != "stop,remove,create,start" {
		t.Fatalf("engine calls = %s", calls)
	}
	if _, err := os.Stat(wrapped.journal); !os.IsNotExist(err) {
		t.Fatalf("recreate journal after finish: %v", err)
	}
	data, _ := json.Marshal(instance.results["bnd-1"])
	if instance.results["bnd-1"].Outcome != protocol.OutcomeRecreated {
		t.Fatalf("result = %s", data)
	}
}

func TestRemoveFailureRestartsTheOriginal(t *testing.T) {
	fake := enginetest.New()
	app := runningApp(fake)
	fake.FailRemove = 1
	instance := newRecreateAgent(t, fake)
	instance.recreate(context.Background(), recreateBinding(), app)
	if calls := strings.Join(fake.CallLog(), ","); calls != "stop,remove,start" {
		t.Fatalf("engine calls = %s", calls)
	}
	original, ok := fake.ByName("app")
	if !ok || original.ID != app.ID || original.State.Status != "running" {
		t.Fatalf("original container = %#v", original)
	}
	result := instance.results["bnd-1"]
	if result.Outcome != protocol.OutcomeRecreateFailed || result.Reason != protocol.ReasonEngineError {
		t.Fatalf("result = %#v", result)
	}
}

func TestInterruptedRecreateIsReported(t *testing.T) {
	cases := map[string]struct {
		present    bool
		inProgress bool
		want       protocol.Outcome
	}{
		"container absent":       {want: protocol.OutcomeRecreateFailed},
		"container present":      {present: true},
		"recreate in this agent": {inProgress: true},
	}
	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			fake := enginetest.New()
			if test.present {
				runningApp(fake)
			}
			instance := newRecreateAgent(t, fake)
			instance.recreating["app"] = test.inProgress
			bound := recreateBinding()
			journal, _ := json.Marshal(recreateJournal{Version: 1, Binding: bound.Binding, Key: bound.Key})
			if err := writeOwnerOnly(instance.paths.RecreateJournal("app"), journal, false); err != nil {
				t.Fatal(err)
			}
			if err := instance.fullReconcile(context.Background()); err != nil {
				t.Fatal(err)
			}
			result := instance.results[bound.Binding]
			if result.Outcome != test.want {
				t.Fatalf("result = %#v, want outcome %q", result, test.want)
			}
			if test.want != "" && result.Reason != protocol.ReasonCreateFailed {
				t.Fatalf("reason = %q", result.Reason)
			}
			// Only a failure not yet sent to the controller keeps a
			// journal beside the recreate in progress.
			_, err := os.Stat(instance.paths.RecreateJournal("app"))
			if kept, want := err == nil, test.inProgress || test.want != ""; kept != want {
				t.Fatalf("recreate journal kept = %v, want %v", kept, want)
			}
		})
	}
}

func TestInterruptionReportSurvivesRestartsUntilSent(t *testing.T) {
	ctx := context.Background()
	paths := newPaths(t)
	bound := recreateBinding()
	first := newRecreateAgentAt(t, enginetest.New(), paths)
	journal, _ := json.Marshal(recreateJournal{Version: 1, Binding: bound.Binding, Key: bound.Key})
	if err := writeOwnerOnly(paths.RecreateJournal("app"), journal, false); err != nil {
		t.Fatal(err)
	}
	// The controller is unreachable: the result is recorded but never sent.
	if err := first.fullReconcile(ctx); err != nil {
		t.Fatal(err)
	}
	first.shutdown()
	second := newRecreateAgentAt(t, enginetest.New(), paths)
	if err := second.fullReconcile(ctx); err != nil {
		t.Fatal(err)
	}
	want := protocol.ContractResult{Binding: bound.Binding, Outcome: protocol.OutcomeRecreateFailed, Reason: protocol.ReasonCreateFailed}
	if result := second.results[bound.Binding]; !sameResult(result, want) {
		t.Fatalf("result after a second restart = %#v, want %#v", result, want)
	}
	second.resultSent(protocol.ContractResult{Binding: "bnd-other", Outcome: protocol.OutcomeRecreateFailed, Reason: protocol.ReasonCreateFailed})
	if _, err := os.Stat(paths.RecreateJournal("app")); err != nil {
		t.Fatalf("journal after another binding's result was sent: %v", err)
	}
	second.resultSent(want)
	if _, err := os.Stat(paths.RecreateJournal("app")); !os.IsNotExist(err) {
		t.Fatalf("journal after its result was sent: %v", err)
	}
}

func TestFailedRecreateKeepsItsJournalUntilSent(t *testing.T) {
	fake := enginetest.New()
	app := runningApp(fake)
	fake.FailStart = 1
	instance := newRecreateAgent(t, fake)
	instance.recreate(context.Background(), recreateBinding(), app)
	want := protocol.ContractResult{Binding: "bnd-1", Outcome: protocol.OutcomeRecreateFailed, Reason: protocol.ReasonStartFailed}
	if result := instance.results["bnd-1"]; !sameResult(result, want) {
		t.Fatalf("result = %#v, want %#v", result, want)
	}
	data, err := os.ReadFile(instance.paths.RecreateJournal("app"))
	var journal recreateJournal
	if err != nil || json.Unmarshal(data, &journal) != nil || !sameResult(journal.result(), want) {
		t.Fatalf("journal = %s, %v; want the failed result", data, err)
	}
}

func TestSessionReportsEachSentMessage(t *testing.T) {
	var written bytes.Buffer
	sent := make(chan protocol.Message, 1)
	session := newControllerSession(protocol.NewConn(readWriter{Reader: &bytes.Buffer{}, Writer: &written}), io.NopCloser(nil),
		func(message protocol.Message) { sent <- message })
	defer close(session.done)
	go session.write()
	result := protocol.ContractResult{Binding: "bnd-1", Outcome: protocol.OutcomeRecreateFailed, Reason: protocol.ReasonCreateFailed}
	session.send(result)
	select {
	case message := <-sent:
		if got, ok := message.(protocol.ContractResult); !ok || !sameResult(got, result) {
			t.Fatalf("sent = %#v", message)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the session did not report the sent message")
	}
	if written.Len() == 0 {
		t.Fatal("nothing was written to the controller connection")
	}
}
