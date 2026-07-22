//go:build linux

// ---
// relationships:
//   verifies: control-interface
// ---

package control

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"
)

func TestContextClientInterruptsAnInFlightExchange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "unit.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan struct{})
	release := make(chan struct{})
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer connection.Close()
		close(accepted)
		<-release
	}()
	defer close(release)

	client, err := NewClient(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	finished := make(chan error, 1)
	go func() {
		_, requestErr := client.StatusContext(ctx)
		finished <- requestErr
	}()
	<-accepted
	cancel()
	select {
	case requestErr := <-finished:
		if requestErr == nil {
			t.Fatal("canceled exchange succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("canceled exchange did not return")
	}
}

func TestContextClientDoesNotDialAfterCancellation(t *testing.T) {
	client, err := NewClient(filepath.Join(t.TempDir(), "absent.sock"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.KeysContext(ctx); err == nil {
		t.Fatal("canceled request succeeded")
	}
}
