// ---
// relationships:
//   verifies: command-line-interface
// ---

package command

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	gossh "golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"

	"github.com/wyrd-company/wyrwood/internal/controller/controllertest"
	"github.com/wyrd-company/wyrwood/internal/openbao/baotest"
	"github.com/wyrd-company/wyrwood/operator"
)

type commandResult struct {
	status         int
	stdout, stderr string
}

func runCommand(t *testing.T, stdin string, args ...string) commandResult {
	t.Helper()
	var stdout, stderr bytes.Buffer
	status := run(args, strings.NewReader(stdin), &stdout, &stderr, dependencies{})
	return commandResult{status, stdout.String(), stderr.String()}
}

func TestOperatorCommandsEndToEnd(t *testing.T) {
	ctx := context.Background()
	running := controllertest.Start(t, baotest.Start(t))
	directory := t.TempDir()
	profile := filepath.Join(directory, "state", "operator.json")
	config := "--config=" + profile

	// A refused host key leaves nothing behind.
	refused := runCommand(t, "n\n", "operator", "login", running.URL, config, "--label", "sample-key")
	if refused.status != exitHostKeyChange || !strings.Contains(refused.stderr, "Accept this controller?") {
		t.Fatalf("refused login = %+v", refused)
	}
	if _, err := os.Stat(profile); !os.IsNotExist(err) {
		t.Fatalf("a refused login saved a profile: %v", err)
	}

	login := runCommand(t, "y\n", "operator", "login", running.URL, config, "--label", "sample-key")
	if login.status != exitNotApproved || !strings.Contains(login.stdout, "Status: pending") || !strings.Contains(login.stdout, "Operator key: SHA256:") {
		t.Fatalf("login = %+v", login)
	}
	info, err := os.Stat(filepath.Join(directory, "state", "operator_key"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("key file = %v, %v", info, err)
	}
	if info, err := os.Stat(profile); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("profile = %v, %v", info, err)
	}
	if strings.Contains(login.stdout+login.stderr, "PRIVATE KEY") {
		t.Fatal("login printed the private key")
	}

	notApproved := runCommand(t, "", "policy", "list", config, "--output", "json")
	var failed failureProjection
	if err := json.Unmarshal([]byte(notApproved.stderr), &failed); err != nil || notApproved.status != exitNotApproved || failed.Error != "not-approved" {
		t.Fatalf("policy list on a pending key = %+v, %+v, %v", notApproved, failed, err)
	}

	keys, err := running.Store().OperatorKeys(ctx)
	if err != nil || len(keys) != 1 || keys[0].Label != "sample-key" {
		t.Fatalf("OperatorKeys() = %+v, %v", keys, err)
	}
	grant := operator.Grant{Agents: []string{"sample-host"}, Policies: []string{"sample-policy", "base-policy"}, Actions: operator.Actions}
	if err := running.ApproveOperatorKey(ctx, keys[0].Fingerprint, "sample-key", grant, "sample-approver"); err != nil {
		t.Fatal(err)
	}
	// A repeat login needs no answer: its host key is pinned and its key is saved.
	if again := runCommand(t, "", "operator", "login", running.URL, config, "--output", "json"); again.status != exitSuccess || !strings.Contains(again.stdout, `"status":"approved"`) {
		t.Fatalf("repeat login = %+v", again)
	}
	if who := runCommand(t, "", "operator", "whoami", config); who.status != exitSuccess || !strings.Contains(who.stdout, "Label:    sample-key") {
		t.Fatalf("whoami = %+v", who)
	}

	source := filepath.Join(directory, "policy.hcl")
	if err := os.WriteFile(source, []byte(`path "kv/data/sample" { capabilities = ["read"] }`), 0o600); err != nil {
		t.Fatal(err)
	}
	put := runCommand(t, "", "policy", "put", "sample-policy", "--file", source, config)
	if put.status != exitSuccess || !strings.Contains(put.stdout, "revision 1") {
		t.Fatalf("policy put = %+v", put)
	}
	if again := runCommand(t, "", "policy", "put", "sample-policy", "--file", source, config); again.status != exitSuccess || !strings.Contains(again.stdout, "revision 1") {
		t.Fatalf("repeat policy put = %+v", again)
	}
	if stdin := runCommand(t, `path "kv/data/base" { capabilities = ["read"] }`, "policy", "put", "base-policy", "--file=-", config); stdin.status != exitSuccess {
		t.Fatalf("policy put from standard input = %+v", stdin)
	}
	if got := runCommand(t, "", "policy", "get", "sample-policy", config); got.status != exitSuccess || !strings.Contains(got.stdout, `path "kv/data/sample"`) {
		t.Fatalf("policy get = %+v", got)
	}
	var policies policiesProjection
	list := runCommand(t, "", "policy", "list", config, "--output", "json")
	if err := json.Unmarshal([]byte(list.stdout), &policies); err != nil || len(policies.Policies) != 2 || policies.Version != outputVersion {
		t.Fatalf("policy list = %+v, %v", list, err)
	}

	agentName := "sample-host"
	approveAgent(t, running, agentName)
	bindArguments := []string{"bind", "--agent", agentName, "--key", "devcontainer:/workspaces/sample|.devcontainer/devcontainer.json",
		"--policy", "base-policy", "--policy", "sample-policy", "--access-group", "1000", "--value", "area=sample", config, "--output", "json"}
	bound := runCommand(t, "", bindArguments...)
	var first bindingProjection
	if err := json.Unmarshal([]byte(bound.stdout), &first); err != nil || bound.status != exitSuccess || first.Binding.ID == "" {
		t.Fatalf("bind = %+v, %v", bound, err)
	}
	if first.Binding.Key.Kind != operator.KeyDevcontainer || first.Binding.Key.Value != "/workspaces/sample|.devcontainer/devcontainer.json" ||
		len(first.Binding.Policies) != 2 || first.Binding.Settings.AccessGroup == nil || *first.Binding.Settings.AccessGroup != 1000 ||
		first.Binding.Settings.Values["area"] != "sample" {
		t.Fatalf("bound binding = %+v", first.Binding)
	}
	var second bindingProjection
	repeat := runCommand(t, "", bindArguments...)
	if err := json.Unmarshal([]byte(repeat.stdout), &second); err != nil || repeat.status != exitSuccess || second.Binding.ID != first.Binding.ID {
		t.Fatalf("repeat bind = %+v, %v", repeat, err)
	}
	differs := runCommand(t, "", "bind", "--agent", agentName, "--key", "devcontainer:/workspaces/sample|.devcontainer/devcontainer.json", "--policy", "base-policy", config)
	if differs.status != exitDiffers || !strings.Contains(differs.stderr, "another selection") {
		t.Fatalf("bind with another selection = %+v", differs)
	}
	outside := runCommand(t, "", "bind", "--agent", "other-host", "--key", "name:app", "--policy", "base-policy", config, "--output", "json")
	if outside.status != exitOutsideGrant || !strings.Contains(outside.stderr, `"outside-grant"`) {
		t.Fatalf("bind outside the grant = %+v", outside)
	}
	human := runCommand(t, "", "binding", "list", "--agent", agentName, config)
	if human.status != exitSuccess || !strings.Contains(human.stdout, first.Binding.ID) || !strings.Contains(human.stdout, "READINESS") {
		t.Fatalf("binding list = %+v", human)
	}
	if got := runCommand(t, "", "binding", "get", first.Binding.ID, config); got.status != exitSuccess || !strings.Contains(got.stdout, "Readiness: ") {
		t.Fatalf("binding get = %+v", got)
	}
	if missing := runCommand(t, "", "binding", "get", "b-unknown", config); missing.status != exitNotFound {
		t.Fatalf("binding get of a missing binding = %+v", missing)
	}
	for _, text := range []string{put.stdout, bound.stdout, human.stdout} {
		for _, private := range []string{"secret-id", "secret_id", "hvs.", "accessor"} {
			if strings.Contains(text, private) {
				t.Fatalf("output holds %q: %s", private, text)
			}
		}
	}
	if removed := runCommand(t, "", "unbind", first.Binding.ID, config); removed.status != exitSuccess || !strings.Contains(removed.stdout, "Binding removed.") {
		t.Fatalf("unbind = %+v", removed)
	}
	if again := runCommand(t, "", "unbind", first.Binding.ID, config, "--output", "json"); again.status != exitSuccess || !strings.Contains(again.stdout, `"removed":false`) {
		t.Fatalf("repeat unbind = %+v", again)
	}
	if byKey := runCommand(t, "", "unbind", "--agent", agentName, "--key", "name:never-bound", config); byKey.status != exitSuccess {
		t.Fatalf("unbind by key = %+v", byKey)
	}

	// A controller that presents another host key is refused with its own status.
	var saved operator.Profile
	data, err := os.ReadFile(profile)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &saved); err != nil {
		t.Fatal(err)
	}
	if saved.HostKey != running.Fingerprint {
		t.Fatalf("pinned host key = %q, want %q", saved.HostKey, running.Fingerprint)
	}
	saved.HostKey = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if err := operator.SaveProfile(profile, saved); err != nil {
		t.Fatal(err)
	}
	if changed := runCommand(t, "", "policy", "list", config); changed.status != exitHostKeyChange {
		t.Fatalf("policy list with another host key = %+v", changed)
	}
	saved.URL = "ssh://" + controllertest.FreeAddress(t)
	if err := operator.SaveProfile(profile, saved); err != nil {
		t.Fatal(err)
	}
	if unreachable := runCommand(t, "", "policy", "list", config); unreachable.status != exitUnreachable {
		t.Fatalf("policy list with no controller = %+v", unreachable)
	}
}

// approveAgent enrolls an agent key with the real SSH server and approves it.
func approveAgent(t *testing.T, running *controllertest.Controller, name string) {
	t.Helper()
	signer, _, err := operator.LoadOrCreateKey(filepath.Join(t.TempDir(), "agent_key"))
	if err != nil {
		t.Fatal(err)
	}
	connection, err := gossh.Dial("tcp", running.SSHAddress, &gossh.ClientConfig{
		User: name, Auth: []gossh.AuthMethod{gossh.PublicKeys(signer)}, HostKeyCallback: gossh.InsecureIgnoreHostKey(),
	})
	if err == nil {
		_ = connection.Close()
		t.Fatal("an unapproved agent key authenticated")
	}
	if err := running.DecideAgent(context.Background(), gossh.FingerprintSHA256(signer.PublicKey()), true, "sample-approver"); err != nil {
		t.Fatal(err)
	}
}

func TestOperatorCommandUsageAndStateFailures(t *testing.T) {
	config := "--config=" + filepath.Join(t.TempDir(), "absent.json")
	for name, attempt := range map[string]struct {
		args   []string
		status int
	}{
		"no subcommand":          {[]string{"operator"}, exitUsage},
		"unknown subcommand":     {[]string{"operator", "logout"}, exitUsage},
		"login needs a URL":      {[]string{"operator", "login", config}, exitUsage},
		"login takes one source": {[]string{"operator", "login", "ssh://sample:22", "--key-file", "a", "--agent-key", "b", config}, exitUsage},
		"login checks its label": {[]string{"operator", "login", "ssh://sample:22", "--label", "not a label", config}, exitUsage},
		"login checks its URL":   {[]string{"operator", "login", "https://sample", "--accept-fingerprint", "SHA256:x", config}, exitUsage},
		"policy needs a verb":    {[]string{"policy"}, exitUsage},
		"put needs a file":       {[]string{"policy", "put", "sample", config}, exitUsage},
		"get needs a name":       {[]string{"policy", "get", config}, exitUsage},
		"file is only for put":   {[]string{"policy", "list", "--file", "x", config}, exitUsage},
		"bind needs an agent":    {[]string{"bind", "--key", "name:app", "--policy", "sample", config}, exitUsage},
		"bind needs a policy":    {[]string{"bind", "--agent", "sample", "--key", "name:app", config}, exitUsage},
		"bind checks its key":    {[]string{"bind", "--agent", "sample", "--key", "bad", "--policy", "sample", config}, exitUsage},
		"bind checks its group":  {[]string{"bind", "--agent", "sample", "--key", "name:app", "--policy", "sample", "--access-group", "-1", config}, exitUsage},
		"bind checks its value":  {[]string{"bind", "--agent", "sample", "--key", "name:app", "--policy", "sample", "--value", "novalue", config}, exitUsage},
		"bind refuses a repeat":  {[]string{"bind", "--agent", "sample", "--agent", "other", "--key", "name:app", "--policy", "sample", config}, exitUsage},
		"unbind needs a target":  {[]string{"unbind", config}, exitUsage},
		"unbind takes one form":  {[]string{"unbind", "b-1", "--agent", "sample", "--key", "name:app", config}, exitUsage},
		"unbind needs an agent":  {[]string{"unbind", "--key", "name:app", config}, exitUsage},
		"binding needs a verb":   {[]string{"binding"}, exitUsage},
		"no saved login":         {[]string{"policy", "list", config}, exitLoginState},
		"no saved login, whoami": {[]string{"operator", "whoami", config}, exitLoginState},
	} {
		t.Run(name, func(t *testing.T) {
			if got := runCommand(t, "", attempt.args...); got.status != attempt.status {
				t.Fatalf("status = %d; want %d; %+v", got.status, attempt.status, got)
			}
		})
	}
}

// A saved login reaches its selected key through SSH_AUTH_SOCK on each command.
func TestOperatorCommandsUseASelectedAgentKey(t *testing.T) {
	ctx := context.Background()
	running := controllertest.Start(t, baotest.Start(t))
	keyring := sshagent.NewKeyring()
	for _, comment := range []string{"unrelated-key", "selected-key"} {
		_, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if err := keyring.Add(sshagent.AddedKey{PrivateKey: private, Comment: comment}); err != nil {
			t.Fatal(err)
		}
	}
	socket := filepath.Join(t.TempDir(), "agent.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			go func() { _ = sshagent.ServeAgent(keyring, connection) }()
		}
	}()
	t.Setenv("SSH_AUTH_SOCK", socket)
	directory := t.TempDir()
	config := "--config=" + filepath.Join(directory, "operator.json")
	login := runCommand(t, "", "operator", "login", running.URL, "--agent-key", "selected-key", "--label", "agent-held", "--accept-fingerprint", running.Fingerprint, config)
	if login.status != exitNotApproved {
		t.Fatalf("login = %+v", login)
	}
	if _, err := os.Stat(filepath.Join(directory, "operator_key")); !os.IsNotExist(err) {
		t.Fatalf("a login with an agent key generated a key file: %v", err)
	}
	keys, err := running.Store().OperatorKeys(ctx)
	if err != nil || len(keys) != 1 {
		t.Fatalf("OperatorKeys() = %+v, %v", keys, err)
	}
	if err := running.ApproveOperatorKey(ctx, keys[0].Fingerprint, "agent-held", operator.Grant{Actions: operator.Actions}, "sample-approver"); err != nil {
		t.Fatal(err)
	}
	if who := runCommand(t, "", "operator", "whoami", config); who.status != exitSuccess || !strings.Contains(who.stdout, keys[0].Fingerprint) {
		t.Fatalf("whoami = %+v", who)
	}
}

func TestOperatorLoginWithASelectedAgentKeyNeedsTheAgent(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	config := "--config=" + filepath.Join(t.TempDir(), "operator.json")
	got := runCommand(t, "", "operator", "login", "ssh://127.0.0.1:1", "--agent-key", "selected", config, "--output", "json")
	if got.status != exitLoginState || !strings.Contains(got.stderr, `"key-selection"`) {
		t.Fatalf("login = %+v", got)
	}
}
