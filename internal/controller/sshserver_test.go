// ---
// relationships:
//   validates: controller
// ---

package controller

import (
	"context"
	"errors"
	"testing"

	gossh "golang.org/x/crypto/ssh"
)

func TestSSHDependencyUpgradePreservesSessionBoundaries(t *testing.T) {
	harness := startHarness(t)
	key := newAgentKey(t)
	if _, err := harness.dial("example-agent", key); err == nil {
		t.Fatal("unapproved key authenticated")
	}
	if err := harness.controller.DecideAgent(context.Background(), gossh.FingerprintSHA256(key.PublicKey()), true, "operator"); err != nil {
		t.Fatal(err)
	}
	connection, err := harness.dial("example-agent", key)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.client.Close()

	for _, request := range []string{"shell", "exec", "unknown-subsystem"} {
		t.Run(request, func(t *testing.T) {
			session, err := connection.client.NewSession()
			if err != nil {
				t.Fatal(err)
			}
			defer session.Close()
			if request == "unknown-subsystem" {
				if err := session.RequestSubsystem("unsupported"); err == nil {
					t.Fatal("unsupported subsystem accepted")
				}
				return
			}
			if request == "shell" {
				err = session.Shell()
			} else {
				err = session.Start("true")
			}
			if err != nil {
				t.Fatal(err)
			}
			var exit *gossh.ExitError
			if err := session.Wait(); !errors.As(err, &exit) || exit.ExitStatus() != 1 {
				t.Fatalf("session result = %v; want exit status 1", err)
			}
		})
	}
	forwarded, err := connection.client.Dial("tcp", "127.0.0.1:1")
	if err == nil {
		_ = forwarded.Close()
		t.Fatal("port forwarding accepted")
	}
	var channelError *gossh.OpenChannelError
	if !errors.As(err, &channelError) || channelError.Reason != gossh.UnknownChannelType {
		t.Fatalf("forwarding error = %v; want unsupported channel type", err)
	}
}
