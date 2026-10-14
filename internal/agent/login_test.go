// ---
// relationships:
//   verifies: agent
// ---

package agent

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

// silentController accepts TCP connections and never sends an SSH banner.
func silentController(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { _ = connection.Close() })
		}
	}()
	return "ssh://" + listener.Addr().String()
}

func TestLoginBoundsTheHandshake(t *testing.T) {
	cases := map[string]struct {
		timeout time.Duration
		cancel  time.Duration
	}{
		"timeout":        {timeout: 200 * time.Millisecond, cancel: time.Hour},
		"context cancel": {timeout: time.Hour, cancel: 200 * time.Millisecond},
	}
	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), test.cancel)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				_, err := Login(ctx, LoginOptions{Paths: newPaths(t), ControllerURL: silentController(t),
					AcceptFingerprint: "SHA256:any", Timeout: test.timeout,
					Hostname: func() (string, error) { return "host-a", nil }})
				done <- err
			}()
			select {
			case err := <-done:
				if !errors.Is(err, ErrUnreachable) {
					t.Fatalf("Login() = %v, want %v", err, ErrUnreachable)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("Login() did not return after the handshake bound")
			}
		})
	}
}
