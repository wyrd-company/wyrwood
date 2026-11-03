// ---
// relationships:
//   verifies: operator-interface
//   uses: ssh-agent-endpoint
// ---

package controller

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/openbao/openbao/api/v2"
	gossh "golang.org/x/crypto/ssh"

	"github.com/wyrd-company/wyrwood/internal/binding"
	"github.com/wyrd-company/wyrwood/internal/events"
	"github.com/wyrd-company/wyrwood/internal/openbao"
	"github.com/wyrd-company/wyrwood/internal/policy"
	"github.com/wyrd-company/wyrwood/internal/protocol"
	"github.com/wyrd-company/wyrwood/internal/sshagent"
	"github.com/wyrd-company/wyrwood/operator"
)

// A Transit key behind a real ssh-agent.sock is the identity: OpenBao signs each
// authentication, and the private key exists nowhere else. The socket offers two
// keys, and only the selected one is recorded.
func TestATransitKeyBehindTheAgentSocketIsAnOperatorIdentity(t *testing.T) {
	ctx := context.Background()
	harness := startHarness(t)
	bao := harness.bao
	bao.CreateTransitKey(t, "sample-ed", "ed25519")
	bao.CreateTransitKey(t, "sample-rsa", "rsa-2048")
	bao.CreateTransitKey(t, "unrelated-ed", "ed25519")
	hcl := `
path "transit/keys/*" { capabilities = ["read"] }
path "transit/sign/*" { capabilities = ["update"] }
`
	if err := bao.Root.Sys().PutPolicy("sample-transit", hcl); err != nil {
		t.Fatal(err)
	}
	secret, err := bao.Root.Auth().Token().Create(&api.TokenCreateRequest{Policies: []string{"sample-transit"}, TTL: "1h"})
	if err != nil {
		t.Fatal(err)
	}
	client, err := openbao.NewClient(openbao.Endpoint{Address: bao.Address, Namespace: bao.Namespace, Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	document := policy.New("sample", hcl)
	document.SSH = &policy.SSH{TransitKeys: []string{"sample-ed", "sample-rsa", "unrelated-ed"}}
	view := binding.View{
		ID: "b-1", ContainerKey: "name:sample", Policy: document.Runtime(policy.DefaultSettings()),
		OpenBao: protocol.OpenBao{Address: bao.Address, Namespace: bao.Namespace},
		Mounts:  binding.Mounts{Transit: "transit", SSH: "ssh"}, Client: client,
		Token: openbao.NewToken(secret.Auth.ClientToken, time.Hour), HasToken: true,
	}
	socket := filepath.Join(t.TempDir(), "ssh-agent.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go sshagent.New(10*time.Second).Serve(listener, func() (binding.View, bool) { return view, true }, func(events.Event) {})

	agent, connection, err := operator.DialAgent(socket)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	for _, name := range []string{"sample-ed", "sample-rsa"} {
		t.Run(name, func(t *testing.T) {
			keys, err := agent.List()
			if err != nil {
				t.Fatal(err)
			}
			var selection string
			for _, key := range keys {
				if key.Comment == "transit:"+name || key.Comment == name {
					selection = key.Comment
				}
			}
			if selection == "" {
				t.Fatalf("the socket does not list %s: %v", name, keys)
			}
			signer, err := operator.SelectAgentKey(agent, selection)
			if err != nil {
				t.Fatal(err)
			}
			settings := harness.operatorConfig(signer)
			before, err := harness.controller.Store().OperatorKeys(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if result, err := operator.Login(ctx, settings, nil); err != nil || result.Approved {
				t.Fatalf("Login() = %+v, %v", result, err)
			}
			after, err := harness.controller.Store().OperatorKeys(ctx)
			if err != nil || len(after) != len(before)+1 {
				t.Fatalf("recorded keys = %+v, %v; want one more than %d", after, err, len(before))
			}
			fingerprint := gossh.FingerprintSHA256(signer.PublicKey())
			if err := harness.controller.ApproveOperatorKey(ctx, fingerprint, name, fullGrant, "sample-approver"); err != nil {
				t.Fatal(err)
			}
			operatorClient, err := operator.Dial(ctx, settings)
			if err != nil {
				t.Fatal(err)
			}
			defer operatorClient.Close()
			if identity, err := operatorClient.Whoami(ctx); err != nil || identity.Fingerprint != fingerprint {
				t.Fatalf("Whoami() = %+v, %v", identity, err)
			}
		})
	}
}
