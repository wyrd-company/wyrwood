// ---
// relationships:
//   verifies:
//     - controller
//     - agent
// ---

// Package baotest runs a real OpenBao dev server for tests. Tests skip when
// no bao executable is available on PATH or at WYRWOOD_BAO.
package baotest

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openbao/openbao/api/v2"
)

// RootToken is the dev server's root token.
const RootToken = "wyrwood-test-root"

// Namespace is the dedicated namespace every fixture lives in, as the
// supported deployment specifies.
const Namespace = "wyrwood"

// ControllerName names the controller's own policy and AppRole, outside the
// managed prefix so the controller cannot rewrite them.
const ControllerName = "controller"

// ControllerPolicy is the bounded controller policy the controller design
// specifies, for the default mounts.
const ControllerPolicy = `
path "sys/policies/acl/wyrwood-*" { capabilities = ["create", "read", "update", "delete", "list"] }
path "auth/approle/role/wyrwood-*" { capabilities = ["create", "read", "update", "delete", "list"] }
path "auth/approle/role/wyrwood-*/role-id" { capabilities = ["read"] }
path "auth/approle/role/wyrwood-*/secret-id" { capabilities = ["create", "update"] }
path "sys/wrapping/wrap" { capabilities = ["update"] }
path "kv/metadata" { capabilities = ["list"] }
path "kv/metadata/*" { capabilities = ["list"] }
path "transit/keys" { capabilities = ["list"] }
path "transit/keys/*" { capabilities = ["create", "read", "update", "list"] }
path "ssh/roles" { capabilities = ["list"] }
path "ssh/roles/*" { capabilities = ["create", "read", "update", "list"] }
path "auth/token/renew-self" { capabilities = ["update"] }
path "auth/token/revoke-accessor" { capabilities = ["update"] }
`

// Server is a running dev server.
type Server struct {
	Address string
	// Namespace is the dedicated namespace the fixtures live in.
	Namespace string
	// Root is a root token client scoped to Namespace.
	Root *api.Client
	// TopLevel is a root token client in the root namespace, outside
	// Namespace.
	TopLevel *api.Client
}

// Executable returns the bao executable path or skips the test.
func Executable(t testing.TB) string {
	t.Helper()
	if path := os.Getenv("WYRWOOD_BAO"); path != "" {
		return path
	}
	path, err := exec.LookPath("bao")
	if err != nil {
		t.Skip("bao executable not available; set WYRWOOD_BAO")
	}
	return path
}

// Start runs a dev server with a dedicated namespace holding KV v2 at kv,
// Transit at transit, an SSH CA at ssh, AppRole at approle, and the
// controller's policy and AppRole, and stops it when the test ends.
func Start(t testing.TB) *Server {
	t.Helper()
	executable := Executable(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()

	var output bytes.Buffer
	command := exec.Command(executable, "server", "-dev", "-dev-root-token-id="+RootToken,
		"-dev-listen-address="+address, "-dev-no-store-token")
	command.Env = []string{"HOME=" + t.TempDir(), "PATH=" + os.Getenv("PATH")}
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = command.Process.Kill()
		_ = command.Wait()
	})
	url := "http://" + address
	deadline := time.Now().Add(20 * time.Second)
	for {
		response, err := http.Get(url + "/v1/sys/health")
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("OpenBao dev server did not start: %s", output.String())
		}
		time.Sleep(100 * time.Millisecond)
	}
	configuration := api.DefaultConfig()
	configuration.Address = url
	topLevel, err := api.NewClient(configuration)
	if err != nil {
		t.Fatal(err)
	}
	topLevel.SetToken(RootToken)
	if _, err := topLevel.Logical().Write("sys/namespaces/"+Namespace, nil); err != nil {
		t.Fatal(err)
	}
	root, err := topLevel.Clone()
	if err != nil {
		t.Fatal(err)
	}
	root.SetToken(RootToken)
	root.SetNamespace(Namespace)
	server := &Server{Address: url, Namespace: Namespace, Root: root, TopLevel: topLevel}
	server.setup(t)
	return server
}

func (server *Server) setup(t testing.TB) {
	t.Helper()
	ctx := context.Background()
	sys := server.Root.Sys()
	must := func(err error) {
		t.Helper()
		if err != nil && !strings.Contains(err.Error(), "path is already in use") {
			t.Fatal(err)
		}
	}
	must(sys.EnableAuthWithOptionsWithContext(ctx, "approle", &api.EnableAuthOptions{Type: "approle"}))
	must(sys.MountWithContext(ctx, "kv", &api.MountInput{Type: "kv", Options: map[string]string{"version": "2"}}))
	must(sys.MountWithContext(ctx, "transit", &api.MountInput{Type: "transit"}))
	must(sys.MountWithContext(ctx, "ssh", &api.MountInput{Type: "ssh"}))
	if _, err := server.Root.Logical().WriteWithContext(ctx, "ssh/config/ca", map[string]any{"generate_signing_key": true, "key_type": "ed25519"}); err != nil {
		t.Fatal(err)
	}
	must(sys.PutPolicyWithContext(ctx, ControllerName, ControllerPolicy))
	if _, err := server.Root.Logical().WriteWithContext(ctx, "auth/approle/role/"+ControllerName, map[string]any{
		"token_policies": []string{ControllerName},
		"token_ttl":      "1h",
	}); err != nil {
		t.Fatal(err)
	}
}

// ControllerCredentials returns a role identifier and a secret identifier
// file for the controller AppRole.
func (server *Server) ControllerCredentials(t testing.TB) (string, string) {
	t.Helper()
	ctx := context.Background()
	role, err := server.Root.Logical().ReadWithContext(ctx, "auth/approle/role/"+ControllerName+"/role-id")
	if err != nil {
		t.Fatal(err)
	}
	secret, err := server.Root.Logical().WriteWithContext(ctx, "auth/approle/role/"+ControllerName+"/secret-id", nil)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "secret-id")
	if err := os.WriteFile(path, []byte(fmt.Sprint(secret.Data["secret_id"])+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return fmt.Sprint(role.Data["role_id"]), path
}

// WriteKV writes a KV v2 secret with the root token.
func (server *Server) WriteKV(t testing.TB, path string, data map[string]any) {
	t.Helper()
	if _, err := server.Root.KVv2("kv").Put(context.Background(), path, data); err != nil {
		t.Fatal(err)
	}
}

// CreateTransitKey creates a Transit key with the root token.
func (server *Server) CreateTransitKey(t testing.TB, name, keyType string) {
	t.Helper()
	if _, err := server.Root.Logical().Write("transit/keys/"+name, map[string]any{"type": keyType}); err != nil {
		t.Fatal(err)
	}
}

// CreateSSHRole creates an SSH-engine user-certificate role with the root token.
func (server *Server) CreateSSHRole(t testing.TB, name, allowedUsers string, ttl string) {
	t.Helper()
	if _, err := server.Root.Logical().Write("ssh/roles/"+name, map[string]any{
		"key_type": "ca", "allow_user_certificates": true, "allowed_users": allowedUsers,
		"default_user": strings.Split(allowedUsers, ",")[0], "ttl": ttl,
		"algorithm_signer": "default",
	}); err != nil {
		t.Fatal(err)
	}
}

// CAPublicKey returns the SSH CA public key in authorized_keys form.
func (server *Server) CAPublicKey(t testing.TB) string {
	t.Helper()
	secret, err := server.Root.Logical().Read("ssh/config/ca")
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprint(secret.Data["public_key"])
}
