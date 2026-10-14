// ---
// relationships:
//   verifies:
//     - agent
//     - container-contract
// ---

package agent

import (
	"context"
	"encoding/json"
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
	paths := newPaths(t)
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
			_, err := os.Stat(instance.paths.RecreateJournal("app"))
			if kept := err == nil; kept != test.inProgress {
				t.Fatalf("recreate journal kept = %v, want %v", kept, test.inProgress)
			}
		})
	}
}
