// ---
// relationships:
//   verifies: ssh-agent-endpoint
// ---

package sshagent

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"

	"github.com/wyrd-company/wyrwood/internal/events"
	"github.com/wyrd-company/wyrwood/internal/policy"
)

func TestNotForwardableSigning(t *testing.T) {
	_, fixture := setup(t)
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	host, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	setRestrictions := func(selected *policy.SSHIdentityNames) {
		fixture.mu.Lock()
		defer fixture.mu.Unlock()
		fixture.view.Policy.SSH.NotForwardable = selected
	}
	restricted := &policy.SSHIdentityNames{TransitKeys: []string{"teal-ed"}, CARoles: []string{"teal-hosts"}}
	bind := func(t *testing.T, client sshagent.ExtendedAgent, forwarding bool) {
		t.Helper()
		if _, err := client.Extension("session-bind@openssh.com", sessionBind(t, host, forwarding, false)); err != nil {
			t.Fatal(err)
		}
	}
	check := func(t *testing.T, client sshagent.ExtendedAgent, denied bool) {
		t.Helper()
		keys, err := client.List()
		if err != nil || len(keys) != 3 {
			t.Fatalf("identity listing changed: %v, %v", keys, err)
		}
		for _, offered := range keys {
			key, err := ssh.ParsePublicKey(offered.Blob)
			if err != nil {
				t.Fatal(err)
			}
			wantDenied := denied && offered.Comment != "teal-rsa"
			flags := sshagent.SignatureFlags(0)
			if offered.Comment == "teal-rsa" {
				flags = sshagent.SignatureFlagRsaSha512
			}
			data := []byte("sample authentication data")
			signature, err := client.SignWithFlags(key, data, flags)
			if wantDenied {
				if err == nil || signature != nil {
					t.Errorf("%s signed on a forwarded connection", offered.Comment)
				}
				fixture.mu.Lock()
				event := fixture.events[len(fixture.events)-1]
				fixture.mu.Unlock()
				if event.Operation != events.OperationSSHSign || event.Outcome != events.OutcomeDenied || event.ErrorCode != events.ErrorPolicyDenied {
					t.Errorf("%s denial event = %#v", offered.Comment, event)
				}
			} else if err != nil || key.Verify(data, signature) != nil {
				t.Errorf("%s signature = %v, %v", offered.Comment, signature, err)
			}
		}
	}
	for _, name := range []string{"unbound", "non-forwarding", "invalid-forwarding", "forwarding", "forwarding-then-non-forwarding", "default-forwardable", "source-specific-selectors", "live-policy"} {
		t.Run(name, func(t *testing.T) {
			setRestrictions(restricted)
			client := dial(t, fixture.socket)
			switch name {
			case "unbound":
				check(t, client, false)
			case "non-forwarding":
				bind(t, client, false)
				check(t, client, false)
			case "invalid-forwarding":
				for _, payload := range [][]byte{nil, sessionBind(t, host, true, true)} {
					if _, err := client.Extension("session-bind@openssh.com", payload); err == nil {
						t.Fatal("invalid forwarding bind accepted")
					}
				}
				check(t, client, false)
			case "forwarding":
				bind(t, client, true)
				check(t, client, true)
				// A second connection on the same socket has no forwarding state.
				check(t, dial(t, fixture.socket), false)
			case "forwarding-then-non-forwarding":
				bind(t, client, true)
				bind(t, client, false)
				check(t, client, true)
			case "default-forwardable":
				setRestrictions(nil)
				bind(t, client, true)
				check(t, client, false)
			case "source-specific-selectors":
				setRestrictions(&policy.SSHIdentityNames{TransitKeys: []string{"teal-hosts"}, CARoles: []string{"teal-ed"}})
				bind(t, client, true)
				check(t, client, false)
			case "live-policy":
				setRestrictions(nil)
				bind(t, client, true)
				check(t, client, false)
				setRestrictions(restricted)
				check(t, client, true)
				setRestrictions(nil)
				check(t, client, false)
			}
		})
	}
}
