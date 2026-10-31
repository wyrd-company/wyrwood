// ---
// relationships:
//   verifies: agent
// ---

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wyrd-company/wyrwood/internal/config"
	"github.com/wyrd-company/wyrwood/internal/engine"
	"github.com/wyrd-company/wyrwood/internal/engine/enginetest"
	"github.com/wyrd-company/wyrwood/internal/events"
	"github.com/wyrd-company/wyrwood/internal/protocol"
)

type heldEngine struct {
	*enginetest.Fake
	calls   atomic.Int32
	entered chan struct{}
	release chan struct{}
}

func (e *heldEngine) List(ctx context.Context) ([]engine.Summary, error) {
	if e.calls.Add(1) == 2 {
		close(e.entered)
		<-e.release
	}
	return e.Fake.List(ctx)
}

func TestAgentRunJoinsEngineWorkerBeforeReleasingState(t *testing.T) {
	paths := newPaths(t)
	if err := os.MkdirAll(paths.State, 0o700); err != nil {
		t.Fatal(err)
	}
	settings, err := config.ParseAgent([]byte("controller:\n  url: ssh://127.0.0.1:1\nconsumers:\n  root: " + filepath.Join(paths.Runtime, "containers") + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	e := &heldEngine{Fake: enginetest.New(), entered: make(chan struct{}), release: make(chan struct{})}
	instance, err := New(Options{Config: settings, Paths: paths, Engine: e})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- instance.Run(ctx) }()
	defer cancel()
	released := false
	defer func() {
		if !released {
			close(e.release)
		}
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("agent did not finish")
		}
	}()
	select {
	case <-e.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("engine worker did not reach held list")
	}
	cancel()
	// The held Engine call still owns state even after cancellation. A new
	// runtime must not acquire the event writer lock until that call settles.
	select {
	case err := <-done:
		done <- err
		t.Fatal("agent returned with an active Engine worker")
	case <-time.After(50 * time.Millisecond):
	}
	if _, err := New(Options{Config: settings, Paths: paths, Engine: e}); !errors.Is(err, events.ErrWriterActive) {
		t.Fatalf("writer lock while worker held: %v", err)
	}
	close(e.release)
	released = true
}

func TestRunDaemonInvalidConfiguration(t *testing.T) {
	if err := RunDaemon(context.Background(), newPaths(t), "dev", nil); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("missing configuration: %v", err)
	}
}

type heldRecreateEngine struct {
	*enginetest.Fake
	entered   chan struct{}
	cancelled chan struct{}
	release   chan struct{}
}

func (e *heldRecreateEngine) Stop(ctx context.Context, _ string, _ time.Duration) error {
	close(e.entered)
	<-ctx.Done()
	close(e.cancelled)
	<-e.release
	return ctx.Err()
}

func TestAgentRunJoinsRecreateBeforeReleasingState(t *testing.T) {
	e := &heldRecreateEngine{Fake: enginetest.New(), entered: make(chan struct{}),
		cancelled: make(chan struct{}), release: make(chan struct{})}
	container := runningApp(e.Fake)
	paths := newPaths(t)
	instance := newRecreateAgentAt(t, e, paths)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- instance.Run(ctx) }()
	var release sync.Once
	defer func() {
		cancel()
		release.Do(func() { close(e.release) })
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("agent did not stop")
		}
	}()
	instance.startRecreate(ctx, recreateBinding(), container)
	select {
	case <-e.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("recreate did not reach Stop")
	}
	cancel()
	<-e.cancelled
	select {
	case err := <-done:
		done <- err
		t.Fatal("Run returned while recreate Stop was held")
	case <-time.After(50 * time.Millisecond):
	}
	duplicate, err := New(Options{Config: instance.config, Paths: paths, Engine: e})
	if duplicate != nil {
		duplicate.shutdown()
	}
	if !errors.Is(err, events.ErrWriterActive) {
		t.Fatalf("replacement admitted while Stop held: %v", err)
	}
	data, err := os.ReadFile(paths.RecreateJournal(container.ShortName()))
	if err != nil {
		t.Fatal(err)
	}
	var journal recreateJournal
	if err := json.Unmarshal(data, &journal); err != nil || journal.Outcome != "" {
		t.Fatalf("held journal: %s, %v", data, err)
	}
	release.Do(func() { close(e.release) })
	select {
	case err := <-done:
		done <- err
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("recreate did not settle")
	}
	data, err = os.ReadFile(paths.RecreateJournal(container.ShortName()))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &journal); err != nil || journal.Outcome != protocol.OutcomeRecreateFailed {
		t.Fatalf("terminal journal: %s, %v", data, err)
	}
	// A stopped instance must reject registration even with a fresh context.
	instance.startRecreate(context.Background(), recreateBinding(), container)
	replacement := newRecreateAgentAt(t, enginetest.New(), paths)
	if err := replacement.fullReconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	replacement.mu.Lock()
	result := replacement.results[recreateBinding().Binding]
	replacement.mu.Unlock()
	if result.Outcome != protocol.OutcomeRecreateFailed {
		t.Fatalf("restart lost result: %#v", result)
	}
}

func TestCancelledRecreateDoesNotAdmitStateWriter(t *testing.T) {
	fake := enginetest.New()
	container := runningApp(fake)
	instance := newRecreateAgent(t, fake)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	instance.startRecreate(ctx, recreateBinding(), container)
	instance.recreateWorkers.Wait()
	if calls := fake.CallLog(); len(calls) != 0 {
		t.Fatalf("cancelled recreate reached Engine: %v", calls)
	}
	if len(instance.results) != 0 || len(instance.recreating) != 0 {
		t.Fatal("cancelled recreate changed state")
	}
	if _, err := os.Stat(instance.paths.RecreateJournal(container.ShortName())); !os.IsNotExist(err) {
		t.Fatalf("cancelled recreate journal: %v", err)
	}
}
