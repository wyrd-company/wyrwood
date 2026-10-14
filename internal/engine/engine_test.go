// ---
// relationships:
//   verifies: agent
// ---

package engine

import (
	"context"
	"encoding/json"
	"errors"
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
	id, err := client.Create(ctx, "wyrwood-engine-test", body)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Remove(context.Background(), id) }()
	select {
	case event := <-stream:
		if event.ID != id || event.Action != "create" {
			t.Fatalf("event = %#v", event)
		}
	case <-ctx.Done():
		t.Fatal("no create event")
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
