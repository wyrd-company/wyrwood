// ---
// relationships:
//   verifies: agent
// ---

package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wyrd-company/wyrwood/internal/config"
	"github.com/wyrd-company/wyrwood/internal/engine"
	"github.com/wyrd-company/wyrwood/internal/engine/enginetest"
	"github.com/wyrd-company/wyrwood/internal/events"
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
