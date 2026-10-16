// ---
// relationships:
//   verifies: engine-proxy
// ---

package engineproxy

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/wyrd-company/wyrwood/internal/engine"
)

func TestReadOnlyProxyAgainstRealEngine(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	original := engine.NewClient("/var/run/docker.sock")
	if _, err := original.List(ctx); err != nil {
		t.Skip("Docker Engine unavailable")
	}
	socket := filepath.Join(t.TempDir(), "proxy.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	proxy := New("/var/run/docker.sock", false, nil)
	go func() { done <- proxy.Serve(ctx, listener) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	client := engine.NewClient(socket)
	if _, err := client.List(ctx); err != nil {
		t.Fatal("container list through real proxy", err)
	}
	// A synthetic identifier makes a leaked write distinguishable: Docker would
	// return not-found, whereas the disabled proxy returns unavailable (403).
	if err := client.Start(ctx, "missing-sample"); err != engine.ErrUnavailable {
		t.Fatalf("write escaped proxy: %v", err)
	}
}
