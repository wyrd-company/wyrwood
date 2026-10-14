// ---
// relationships:
//   verifies: agent
// ---

package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/wyrd-company/wyrwood/internal/consumer"
	"github.com/wyrd-company/wyrwood/internal/engine"
	"github.com/wyrd-company/wyrwood/internal/engine/enginetest"
	"github.com/wyrd-company/wyrwood/internal/events"
	"github.com/wyrd-company/wyrwood/internal/policy"
	"github.com/wyrd-company/wyrwood/internal/protocol"
)

// newBoundApp returns an agent observing a running container app bound by a
// report policy, after one full reconcile.
func newBoundApp(t *testing.T) (*enginetest.Fake, *Agent) {
	t.Helper()
	ctx := context.Background()
	fake := enginetest.New()
	runningApp(fake)
	instance := newRecreateAgent(t, fake)
	document := policy.New("report", `path "kv/data/app/*" { capabilities = ["read"] }`)
	instance.applyPolicySet(ctx, protocol.PolicySet{OpenBao: protocol.OpenBao{Address: "http://127.0.0.1:1"},
		Bindings: []protocol.Binding{{Binding: "bnd-1", Key: protocol.Key{Kind: protocol.KeyName, Value: "app"}, Policy: document}}})
	if err := instance.fullReconcile(ctx); err != nil {
		t.Fatal(err)
	}
	return fake, instance
}

func TestTransientInspectFailureKeepsTheConsumerDirectory(t *testing.T) {
	ctx := context.Background()
	fake, instance := newBoundApp(t)
	path := instance.root.DirectoryPath("app")
	// The container mounts the directory by inode; hold it as the container would.
	held, err := os.Open(path)
	if err != nil {
		t.Fatalf("consumer directory: %v", err)
	}
	defer held.Close()
	before, err := held.Stat()
	if err != nil {
		t.Fatal(err)
	}
	fake.FailInspect = 1
	if err := instance.fullReconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if err := instance.fullReconcile(ctx); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil || !os.SameFile(before, after) {
		t.Fatalf("consumer directory replaced after a transient inspect failure: %v", err)
	}
	if _, err := os.Stat(filepath.Join(path, consumer.VaultSocket)); err != nil {
		t.Fatalf("vault socket after recovery: %v", err)
	}
	recorded := instance.events.Recent(eventRetention)
	if len(recorded) == 0 {
		t.Fatal("no events recorded")
	}
	for _, event := range recorded {
		if event.Operation == events.OperationContainerGone {
			t.Fatalf("container-gone recorded for a container that still exists")
		}
	}
}

func TestInspectNotFoundRemovesTheContainer(t *testing.T) {
	fake, instance := newBoundApp(t)
	// The container is destroyed between list and inspect.
	fake.FailInspect = 1
	fake.InspectError = engine.ErrNotFound
	if err := instance.fullReconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(instance.containers) != 0 {
		t.Fatalf("containers after confirmed absence = %d, want 0", len(instance.containers))
	}
}

func TestInterruptedRecreateWaitsForAnUninspectedContainer(t *testing.T) {
	fake := enginetest.New()
	runningApp(fake)
	instance := newRecreateAgent(t, fake)
	bound := recreateBinding()
	journal, _ := json.Marshal(recreateJournal{Version: 1, Binding: bound.Binding, Key: bound.Key})
	if err := writeOwnerOnly(instance.paths.RecreateJournal("app"), journal, false); err != nil {
		t.Fatal(err)
	}
	// The agent has never inspected app, so it cannot know its name.
	fake.FailInspect = 1
	if err := instance.fullReconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if result, ok := instance.results[bound.Binding]; ok {
		t.Fatalf("result while a container is uninspected = %#v", result)
	}
	if _, err := os.Stat(instance.paths.RecreateJournal("app")); err != nil {
		t.Fatalf("recreate journal while a container is uninspected: %v", err)
	}
}
