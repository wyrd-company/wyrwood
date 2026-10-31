// ---
// relationships:
//   verifies: controller
// ---

package command

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestControllerServicesDisabled(t *testing.T) {
	expected := errors.New("controller failure")
	err := runControllerServices(context.Background(), false,
		func(context.Context) error { return expected },
		func(context.Context) error { t.Fatal("local agent started without opt-in"); return nil })
	if !errors.Is(err, expected) {
		t.Fatal(err)
	}
}

func TestControllerServicesJoinBothOnFailure(t *testing.T) {
	for _, failing := range []string{"controller", "agent"} {
		t.Run(failing, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			started := make(chan struct{})
			stopped := false
			expected := errors.New("startup failure")
			cleanup := errors.New("cleanup failure")
			fail := func(context.Context) error { <-started; return expected }
			peer := func(ctx context.Context) error { close(started); <-ctx.Done(); stopped = true; return cleanup }
			serve, run := fail, peer
			if failing == "agent" {
				serve, run = peer, fail
			}
			err := runControllerServices(ctx, true, serve, run)
			if ctx.Err() != nil {
				t.Fatal("peer was not cancelled by service failure")
			}
			if !stopped || !errors.Is(err, expected) || !errors.Is(err, cleanup) {
				t.Fatalf("stopped=%v err=%v", stopped, err)
			}
		})
	}
}

func TestControllerServicesCancelBoth(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{}, 2)
	stopped := make(chan struct{}, 2)
	service := func(ctx context.Context) error {
		started <- struct{}{}
		<-ctx.Done()
		stopped <- struct{}{}
		return nil
	}
	done := make(chan error, 1)
	go func() { done <- runControllerServices(ctx, true, service, service) }()
	defer cancel()
	for i := 0; i < 2; i++ {
		<-started
	}
	cancel()
	select {
	case err := <-done:
		if err != nil || len(stopped) != 2 {
			t.Fatalf("stopped=%d err=%v", len(stopped), err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("services did not stop")
	}
}
