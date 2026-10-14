// ---
// relationships:
//   verifies: agent
// ---

package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"
)

func TestEventsListAndInspectAgainstRealEngine(t *testing.T) {
	client := NewClient("/var/run/docker.sock")
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if _, err := client.List(ctx); err != nil {
		t.Skip("Docker Engine not reachable")
	}
	image := os.Getenv("WYRWOOD_TEST_IMAGE")
	if image == "" {
		image = "openbao/openbao:2.4.1"
	}
	if _, err := client.ImageID(ctx, image); err != nil {
		t.Skipf("test image %s not present", image)
	}
	stream, _ := client.Events(ctx)
	body, _ := json.Marshal(map[string]any{"Image": image, "Entrypoint": []string{"/bin/true"}, "Env": []string{"A=1"}})
	// The stream reports every container on the engine. A decoy created
	// first guarantees an unrelated event precedes the fixture's.
	decoy, err := client.Create(ctx, "wyrwood-engine-test-decoy", body)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Remove(context.Background(), decoy) }()
	id, err := client.Create(ctx, "wyrwood-engine-test", body)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Remove(context.Background(), id) }()
	if err := awaitEvent(ctx, stream, id, "create"); err != nil {
		t.Fatal(err)
	}
	container, err := client.Inspect(ctx, id)
	if err != nil || container.ShortName() != "wyrwood-engine-test" || container.State.Status != "created" {
		t.Fatalf("Inspect() = %#v, %v", container, err)
	}
	if value, ok := container.EnvValue("A"); !ok || value != "1" {
		t.Fatalf("EnvValue() = %q, %v", value, ok)
	}
	if _, err := client.Inspect(ctx, "wyrwood-missing-container"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Inspect(missing) = %v", err)
	}
	if _, err := NewClient("/nonexistent.sock").List(ctx); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("List(unreachable) = %v", err)
	}
}

// awaitEvent reads stream until it reports action for the container id,
// skipping events for other containers and other actions.
func awaitEvent(ctx context.Context, stream <-chan Event, id, action string) error {
	for {
		select {
		case event, ok := <-stream:
			if !ok {
				return fmt.Errorf("event stream ended before %s %s", action, id)
			}
			if event.ID == id && event.Action == action {
				return nil
			}
		case <-ctx.Done():
			return fmt.Errorf("no %s event for %s: %w", action, id, ctx.Err())
		}
	}
}

func TestAwaitEventSkipsUnrelatedEvents(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream := make(chan Event, 3)
	stream <- Event{ID: "other", Action: "create"}
	stream <- Event{ID: "fixture", Action: "start"}
	stream <- Event{ID: "fixture", Action: "create"}
	if err := awaitEvent(ctx, stream, "fixture", "create"); err != nil {
		t.Fatalf("awaitEvent() = %v", err)
	}
	close(stream)
	if err := awaitEvent(ctx, stream, "fixture", "create"); err == nil {
		t.Fatal("awaitEvent(ended stream) = nil")
	}
	expired, stop := context.WithCancel(context.Background())
	stop()
	if err := awaitEvent(expired, make(chan Event), "fixture", "create"); !errors.Is(err, context.Canceled) {
		t.Fatalf("awaitEvent(cancelled) = %v", err)
	}
}
