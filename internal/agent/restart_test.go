// ---
// relationships:
//   verifies: agent
// ---

package agent

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/wyrd-company/wyrwood/internal/consumer"
	"github.com/wyrd-company/wyrwood/internal/engine"
	"github.com/wyrd-company/wyrwood/internal/engine/enginetest"
	"github.com/wyrd-company/wyrwood/internal/events"
	"github.com/wyrd-company/wyrwood/internal/policy"
	"github.com/wyrd-company/wyrwood/internal/protocol"
)

// bootFailure is the error Docker 29 recorded for a container whose consumer
// directory was missing when the daemon restarted it.
func bootFailure(path string) string {
	return "failed to create task for container: failed to create shim task: OCI runtime create failed: runc create failed: " +
		"unable to start container process: error during container init: failed to fulfil mount request: open " + path + ": no such file or directory"
}

func failedApp(fake *enginetest.Fake, instance *Agent, policyName string) engine.Container {
	path := instance.root.DirectoryPath("app")
	app := engine.Container{Name: "/app", Mounts: []engine.Mount{{Type: "bind", Source: path, Destination: "/run/wyrwood"}}}
	app.State.Status = "exited"
	app.State.Error = bootFailure(path)
	app.HostConfig.RestartPolicy.Name = policyName
	fake.Add(app)
	added, _ := fake.ByName("app")
	return added
}

func appBinding() protocol.Binding {
	document := policy.New("report", policy.StarterHCL).Runtime(policy.DefaultSettings())
	return protocol.Binding{Binding: "bnd-1", Key: protocol.Key{Kind: protocol.KeyName, Value: "app"}, Policy: document, Assignment: document.Identity()}
}

func bindApp(instance *Agent) {
	instance.applyPolicySet(context.Background(), protocol.PolicySet{OpenBao: protocol.OpenBao{Address: "http://127.0.0.1:1"}, Bindings: []protocol.Binding{appBinding()}})
}

func startCount(fake *enginetest.Fake) int {
	count := 0
	for _, call := range fake.CallLog() {
		if call == "start" {
			count++
		}
	}
	return count
}

// socketsAtStart fails unless both sockets exist when the engine is asked to start.
type socketsAtStart struct {
	*enginetest.Fake
	t         *testing.T
	directory string
}

func (wrapped socketsAtStart) Start(ctx context.Context, id string) error {
	for _, name := range []string{consumer.VaultSocket, consumer.SSHAgentSocket} {
		if _, err := os.Stat(filepath.Join(wrapped.directory, name)); err != nil {
			wrapped.t.Errorf("socket absent at start: %v", err)
		}
	}
	return wrapped.Fake.Start(ctx, id)
}

func TestStartsContainerWhoseStartFailedOnItsConsumerDirectory(t *testing.T) {
	for _, policyName := range []string{"always", "unless-stopped", "on-failure"} {
		t.Run(policyName, func(t *testing.T) {
			fake := enginetest.New()
			paths := newPaths(t)
			instance := newRecreateAgentAt(t, socketsAtStart{Fake: fake, t: t, directory: filepath.Join(paths.Runtime, "containers", "app")}, paths)
			instance.config.AllowRecreate = false
			app := failedApp(fake, instance, policyName)
			bindApp(instance)
			if err := instance.fullReconcile(context.Background()); err != nil {
				t.Fatal(err)
			}
			instance.engineWorkers.Wait()
			if got := fake.CallLog(); !slices.Equal(got, []string{"start"}) {
				t.Fatalf("engine calls = %v, want one start", got)
			}
			started, err := fake.Inspect(context.Background(), app.ID)
			if err != nil || started.State.Status != "running" {
				t.Fatalf("container = %q, %v", started.State.Status, err)
			}
			recorded := false
			for _, event := range instance.events.Recent(eventRetention) {
				if event.Operation == events.OperationContainerStarted && event.Outcome == events.OutcomeOK && event.Binding == "bnd-1" {
					recorded = true
				}
			}
			if !recorded {
				t.Fatal("no container-started event")
			}
		})
	}
}

func TestLeavesOtherStoppedContainersAlone(t *testing.T) {
	path := func(instance *Agent) string { return instance.root.DirectoryPath("app") }
	cases := map[string]func(*Agent, *engine.Container){
		"restart policy no":  func(_ *Agent, app *engine.Container) { app.HostConfig.RestartPolicy.Name = "no" },
		"stopped on purpose": func(_ *Agent, app *engine.Container) { app.State.Error = "" },
		"never started":      func(_ *Agent, app *engine.Container) { app.State.Status = "created" },
		"already running":    func(_ *Agent, app *engine.Container) { app.State.Status = "running" },
		"other error":        func(instance *Agent, app *engine.Container) { app.State.Error = "exec: no such file or directory" },
		"other directory":    func(instance *Agent, app *engine.Container) { app.State.Error = bootFailure(path(instance) + "2") },
		"not mounted":        func(_ *Agent, app *engine.Container) { app.Mounts = nil },
		"permission denied": func(instance *Agent, app *engine.Container) {
			app.State.Error = "failed to fulfil mount request: open " + path(instance) + ": permission denied"
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			fake := enginetest.New()
			instance := newRecreateAgent(t, fake)
			app := failedApp(fake, instance, "unless-stopped")
			fake.Destroy(app.ID)
			change(instance, &app)
			fake.Add(app)
			bindApp(instance)
			if err := instance.fullReconcile(context.Background()); err != nil {
				t.Fatal(err)
			}
			instance.engineWorkers.Wait()
			if count := startCount(fake); count != 0 {
				t.Fatalf("starts = %d, want 0", count)
			}
		})
	}
}

func TestDoesNotStartAnUnboundContainer(t *testing.T) {
	fake := enginetest.New()
	instance := newRecreateAgent(t, fake)
	failedApp(fake, instance, "always")
	if err := instance.fullReconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	instance.engineWorkers.Wait()
	if count := startCount(fake); count != 0 {
		t.Fatalf("starts = %d, want 0", count)
	}
}

func TestDoesNotStartBeforeSocketsAreReady(t *testing.T) {
	fake := enginetest.New()
	instance := newRecreateAgent(t, fake)
	failedApp(fake, instance, "always")
	instance.endpoints = nil // no listeners are created
	bindApp(instance)
	if err := instance.fullReconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	instance.engineWorkers.Wait()
	if count := startCount(fake); count != 0 {
		t.Fatalf("starts = %d, want 0", count)
	}
}

func TestDecidesAgainOnAFreshInspect(t *testing.T) {
	fake := enginetest.New()
	instance := newRecreateAgent(t, fake)
	failedApp(fake, instance, "always")
	if err := instance.fullReconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	// The observation still shows the failure; the engine has moved on.
	current, _ := fake.ByName("app")
	if err := fake.Start(context.Background(), current.ID); err != nil {
		t.Fatal(err)
	}
	fake.Calls = nil
	bindApp(instance)
	instance.engineWorkers.Wait()
	if count := startCount(fake); count != 0 {
		t.Fatalf("starts = %d, want 0", count)
	}
}

func TestFailedStartIsRetriedOnlyAfterTheReconcileInterval(t *testing.T) {
	ctx := context.Background()
	fake := enginetest.New()
	instance := newRecreateAgent(t, fake)
	app := failedApp(fake, instance, "always")
	fake.FailStart = 1
	bindApp(instance)
	if err := instance.fullReconcile(ctx); err != nil {
		t.Fatal(err)
	}
	instance.engineWorkers.Wait()
	for range 3 {
		if err := instance.fullReconcile(ctx); err != nil {
			t.Fatal(err)
		}
		instance.engineWorkers.Wait()
	}
	if count := startCount(fake); count != 1 {
		t.Fatalf("starts within the interval = %d, want 1", count)
	}
	failed := false
	for _, event := range instance.events.Recent(eventRetention) {
		if event.Operation == events.OperationContainerStarted && event.Outcome == events.OutcomeFailed && event.ErrorCode == events.ErrorEngineUnavailable {
			failed = true
		}
	}
	if !failed {
		t.Fatal("no failed container-started event")
	}
	instance.mu.Lock()
	instance.startAttempts[app.ID] = time.Now().Add(-reconcileInterval)
	instance.mu.Unlock()
	if err := instance.fullReconcile(ctx); err != nil {
		t.Fatal(err)
	}
	instance.engineWorkers.Wait()
	if count := startCount(fake); count != 2 {
		t.Fatalf("starts after the interval = %d, want 2", count)
	}
}

func TestForgetsAttemptWhenTheFailureEnds(t *testing.T) {
	ctx := context.Background()
	fake := enginetest.New()
	instance := newRecreateAgent(t, fake)
	failedApp(fake, instance, "always")
	bindApp(instance)
	if err := instance.fullReconcile(ctx); err != nil {
		t.Fatal(err)
	}
	instance.engineWorkers.Wait()
	current, _ := fake.ByName("app")
	current.State.Status, current.State.Error = "running", ""
	fake.Destroy(current.ID)
	fake.Add(current)
	if err := instance.fullReconcile(ctx); err != nil {
		t.Fatal(err)
	}
	instance.mu.Lock()
	defer instance.mu.Unlock()
	if len(instance.startAttempts) != 0 {
		t.Fatalf("attempts = %v", instance.startAttempts)
	}
}

// changeDuringDecision runs change during the inspect of the start decision,
// which is the first inspect after a start attempt is admitted.
type changeDuringDecision struct {
	*enginetest.Fake
	instance *Agent
	change   func()
}

func (wrapped *changeDuringDecision) Inspect(ctx context.Context, id string) (engine.Container, error) {
	wrapped.instance.mu.Lock()
	armed := len(wrapped.instance.startAttempts) > 0 && wrapped.change != nil
	wrapped.instance.mu.Unlock()
	if armed {
		change := wrapped.change
		wrapped.change = nil
		change()
	}
	return wrapped.Fake.Inspect(ctx, id)
}

// decideWith runs one start decision with change applied during its inspect,
// and fails unless the decision began and no start followed.
func decideWith(t *testing.T, change func(*Agent)) {
	t.Helper()
	fake := enginetest.New()
	wrapped := &changeDuringDecision{Fake: fake}
	instance := newRecreateAgent(t, wrapped)
	wrapped.instance = instance
	wrapped.change = func() { change(instance) }
	failedApp(fake, instance, "always")
	bindApp(instance)
	if err := instance.fullReconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	instance.engineWorkers.Wait()
	instance.mu.Lock()
	attempts := len(instance.startAttempts)
	instance.mu.Unlock()
	if attempts != 1 || wrapped.change != nil {
		t.Fatalf("attempts = %d, change pending = %t: the decision did not begin", attempts, wrapped.change != nil)
	}
	if count := startCount(fake); count != 0 {
		t.Fatalf("starts = %d, want 0", count)
	}
}

func TestDoesNotStartWhenTheBindingIsWithdrawnDuringTheDecision(t *testing.T) {
	decideWith(t, func(instance *Agent) { instance.unbind(context.Background(), "bnd-1") })
}

func TestDoesNotStartWhenSocketsCloseDuringTheDecision(t *testing.T) {
	decideWith(t, func(instance *Agent) {
		instance.mu.Lock()
		defer instance.mu.Unlock()
		instance.consumers["app"].listeners = nil
	})
}

func TestLeavesAContainerBeingRecreatedAlone(t *testing.T) {
	ctx := context.Background()
	t.Run("already recreating", func(t *testing.T) {
		fake := enginetest.New()
		instance := newRecreateAgent(t, fake)
		failedApp(fake, instance, "always")
		instance.recreating["app"] = true
		bindApp(instance)
		if err := instance.fullReconcile(ctx); err != nil {
			t.Fatal(err)
		}
		instance.engineWorkers.Wait()
		if count := startCount(fake); count != 0 {
			t.Fatalf("starts = %d, want 0", count)
		}
	})
	t.Run("begins during the decision", func(t *testing.T) {
		decideWith(t, func(instance *Agent) {
			instance.mu.Lock()
			defer instance.mu.Unlock()
			instance.recreating["app"] = true
		})
	})
}

func TestNoStartIsAdmittedWhileStopping(t *testing.T) {
	fake := enginetest.New()
	instance := newRecreateAgent(t, fake)
	failedApp(fake, instance, "always")
	instance.stopping = true
	bindApp(instance)
	if err := instance.fullReconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	instance.engineWorkers.Wait()
	if count := startCount(fake); count != 0 {
		t.Fatalf("starts = %d, want 0", count)
	}
}
