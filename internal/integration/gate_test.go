//go:build integration

// ---
// relationships:
//   verifies:
//     - agent
//     - controller
//     - container-contract
//     - vault-socket-proxy
//     - ssh-agent-endpoint
//     - operational-events
// ---

// Package integration holds the Linux integration gate: a real Docker
// Engine, a real OpenBao dev server, a real controller and agent, and a
// container created by the devcontainer CLI.
package integration

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	agentclient "golang.org/x/crypto/ssh/agent"

	"github.com/wyrd-company/wyrwood/internal/agent"
	"github.com/wyrd-company/wyrwood/internal/binding"
	"github.com/wyrd-company/wyrwood/internal/config"
	"github.com/wyrd-company/wyrwood/internal/consumer"
	"github.com/wyrd-company/wyrwood/internal/contract"
	"github.com/wyrd-company/wyrwood/internal/controller/controllertest"
	"github.com/wyrd-company/wyrwood/internal/engine"
	"github.com/wyrd-company/wyrwood/internal/openbao/baotest"
	"github.com/wyrd-company/wyrwood/internal/policy"
	"github.com/wyrd-company/wyrwood/internal/protocol"
	"github.com/wyrd-company/wyrwood/internal/sshagent"
	"github.com/wyrd-company/wyrwood/internal/vaultproxy"
)

const (
	gateHCL = `
path "kv/data/teams/teal/*" { capabilities = ["read"] }
path "transit/keys/teal-*" { capabilities = ["read"] }
path "transit/sign/teal-*" { capabilities = ["update"] }
path "ssh/sign/teal-hosts" { capabilities = ["update"] }
`
	gateSecret   = "teal-secret-value"
	gateEnvValue = "gate-environment-value"
)

type endpoints struct {
	vault *vaultproxy.Proxy
	ssh   *sshagent.Endpoint
}

func (set endpoints) ServeVault(listener net.Listener, lookup binding.Lookup, record binding.Recorder) {
	set.vault.Serve(listener, lookup, record)
}

func (set endpoints) ServeSSHAgent(listener net.Listener, lookup binding.Lookup, record binding.Recorder) {
	set.ssh.Serve(listener, lookup, record)
}

func require(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("the gate runs as root: it binds sockets the engine mounts and runs sshd")
	}
	for _, tool := range []string{"docker", "devcontainer", "ssh-keygen", "/usr/sbin/sshd"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is required", tool)
		}
	}
	baotest.Executable(t)
}

func run(t *testing.T, name string, arguments ...string) string {
	t.Helper()
	command := exec.Command(name, arguments...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(arguments, " "), err, output)
	}
	return string(output)
}

func gateImage(t *testing.T) string {
	t.Helper()
	if image := os.Getenv("WYRWOOD_GATE_IMAGE"); image != "" {
		return image
	}
	run(t, "docker", "build", "--quiet", "--tag", "wyrwood-gate:local", "testdata")
	return "wyrwood-gate:local"
}

func eventually(t *testing.T, what string, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

type runningAgent struct {
	cancel context.CancelFunc
	done   chan error
}

func (running *runningAgent) stop() {
	if running.cancel != nil {
		running.cancel()
		<-running.done
		running.cancel = nil
	}
}

func startAgent(t *testing.T, paths agent.Paths, root string) *runningAgent {
	t.Helper()
	configuration, err := config.LoadAgent(paths.Config)
	if err != nil {
		t.Fatal(err)
	}
	configuration.ConsumerRoot = root
	configuration.AllowRecreate = true
	configuration.ControllerTimeout = 3 * time.Second
	instance, err := agent.New(agent.Options{
		Config: configuration, Paths: paths, Engine: engine.NewClient(configuration.EngineSocket), Hostname: "gate-host",
		Endpoints: endpoints{vault: vaultproxy.New(10 * time.Second), ssh: sshagent.New(30 * time.Second)},
		Log:       os.Stderr,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	running := &runningAgent{cancel: cancel, done: make(chan error, 1)}
	go func() { running.done <- instance.Run(ctx) }()
	t.Cleanup(running.stop)
	return running
}

func startSSHD(t *testing.T, caPublicKey string) int {
	t.Helper()
	directory := t.TempDir()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	hostKey := filepath.Join(directory, "host_key")
	run(t, "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", hostKey)
	caFile := filepath.Join(directory, "ca.pub")
	_ = os.WriteFile(caFile, []byte(caPublicKey), 0o644)
	configuration := filepath.Join(directory, "sshd_config")
	_ = os.WriteFile(configuration, []byte(fmt.Sprintf(`Port %d
ListenAddress 127.0.0.1
HostKey %s
PidFile %s/sshd.pid
AuthorizedKeysFile none
TrustedUserCAKeys %s
PermitRootLogin prohibit-password
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
StrictModes no
`, port, hostKey, directory, caFile)), 0o600)
	_ = os.MkdirAll("/run/sshd", 0o755)
	server := exec.Command("/usr/sbin/sshd", "-D", "-e", "-f", configuration)
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Process.Kill(); _ = server.Wait() })
	eventually(t, "sshd", 10*time.Second, func() bool {
		connection, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			_ = connection.Close()
		}
		return err == nil
	})
	return port
}

type devcontainer struct {
	workspace string
}

func (container devcontainer) exec(t *testing.T, arguments ...string) (string, error) {
	t.Helper()
	command := exec.Command("devcontainer", append([]string{"exec", "--workspace-folder", container.workspace}, arguments...)...)
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	err := command.Run()
	return output.String(), err
}

func (container devcontainer) id(t *testing.T) string {
	t.Helper()
	output := run(t, "docker", "ps", "--all", "--quiet", "--no-trunc",
		"--filter", "label=devcontainer.local_folder="+container.workspace)
	return strings.TrimSpace(output)
}

func TestLinuxIntegrationGate(t *testing.T) {
	require(t)
	ctx := context.Background()
	image := gateImage(t)

	bao := baotest.Start(t)
	bao.WriteKV(t, "teams/teal/example", map[string]any{"value": gateSecret})
	bao.CreateTransitKey(t, "teal-signing", "ed25519")
	bao.CreateSSHRole(t, "teal-hosts", "root", "30m")
	controllerState := t.TempDir()
	controller := controllertest.StartIn(t, bao, controllerState, controllertest.FreeAddress(t))
	sshPort := startSSHD(t, bao.CAPublicKey(t))

	base := t.TempDir()
	paths := agent.Paths{Config: filepath.Join(base, "etc", "agent.yml"), State: filepath.Join(base, "state"), Runtime: filepath.Join(base, "run")}
	consumerRoot := filepath.Join(base, "run", "containers")
	hostname := func() (string, error) { return "gate-host", nil }
	login, err := agent.Login(ctx, agent.LoginOptions{Paths: paths, ControllerURL: controller.URL, AcceptFingerprint: controller.Fingerprint, Hostname: hostname})
	if err != nil || login.Approved {
		t.Fatalf("first login = %#v, %v", login, err)
	}
	if err := controller.DecideAgent(ctx, login.AgentFingerprint, true, "gate-operator"); err != nil {
		t.Fatal(err)
	}
	if login, err = agent.Login(ctx, agent.LoginOptions{Paths: paths, ControllerURL: controller.URL, AcceptFingerprint: controller.Fingerprint, Hostname: hostname}); err != nil || !login.Approved {
		t.Fatalf("second login = %#v, %v", login, err)
	}

	// A devcontainer created by the devcontainer CLI, with no Wyrwood mount.
	workspace := t.TempDir()
	_ = os.MkdirAll(filepath.Join(workspace, ".devcontainer"), 0o755)
	definition, _ := json.Marshal(map[string]any{
		"image": image, "runArgs": []string{"--network=host"}, "overrideCommand": true,
		"containerEnv": map[string]string{"GATE_ENV": gateEnvValue},
	})
	_ = os.WriteFile(filepath.Join(workspace, ".devcontainer", "devcontainer.json"), definition, 0o644)
	container := devcontainer{workspace: workspace}
	run(t, "devcontainer", "up", "--workspace-folder", workspace)
	t.Cleanup(func() {
		if id := container.id(t); id != "" {
			_ = exec.Command("docker", "rm", "--force", "--volumes", id).Run()
		}
	})
	originalID := container.id(t)

	running := startAgent(t, paths, consumerRoot)
	eventually(t, "inventory", 30*time.Second, func() bool {
		containers, _, _ := controller.Store().Inventory(ctx, "gate-host")
		for _, reported := range containers {
			if reported.ID == originalID {
				return true
			}
		}
		return false
	})

	document := policy.New("teal", gateHCL)
	document.SSH = &policy.SSH{TransitKeys: []string{"teal-signing"}, CARoles: []string{"teal-hosts"}}
	document.Contract.Enforcement = policy.EnforcementRecreate
	if _, err := controller.SavePolicy(ctx, document, "gate-operator"); err != nil {
		t.Fatal(err)
	}
	var key protocol.Key
	containers, _, _ := controller.Store().Inventory(ctx, "gate-host")
	for _, reported := range containers {
		if reported.ID == originalID {
			key = reported.Keys[0]
		}
	}
	if key.Kind != protocol.KeyDevcontainer {
		t.Fatalf("most stable key = %#v", key)
	}
	bound, err := controller.CreateBinding(ctx, "gate-host", key, "teal", "gate-operator")
	if err != nil {
		t.Fatal(err)
	}

	// Recreate enforcement applies the contract once; the devcontainer CLI
	// finds the recreated container by the same labels.
	eventually(t, "a conforming recreated container", 2*time.Minute, func() bool {
		results, _ := controller.Store().ContractResults(ctx)
		return results[bound.ID].Outcome == protocol.OutcomeConforming && container.id(t) != originalID && container.id(t) != ""
	})
	consumerDirectory := ""
	for _, line := range strings.Split(run(t, "docker", "inspect", "--format", "{{range .Mounts}}{{.Source}}={{.Destination}}\n{{end}}", container.id(t)), "\n") {
		if strings.HasSuffix(line, "=/run/wyrwood") {
			consumerDirectory = strings.TrimSuffix(line, "=/run/wyrwood")
		}
	}
	if !strings.HasPrefix(consumerDirectory, consumerRoot+"/") {
		t.Fatalf("recreated container does not mount its consumer directory: %q", consumerDirectory)
	}

	eventually(t, "bao kv get inside the container", time.Minute, func() bool {
		output, err := container.exec(t, "bao", "kv", "get", "-field=value", "kv/teams/teal/example")
		return err == nil && strings.TrimSpace(output) == gateSecret
	})
	listing, err := container.exec(t, "ssh-add", "-L")
	if err != nil || strings.Count(strings.TrimSpace(listing), "\n") != 1 || !strings.Contains(listing, "teal-signing") || !strings.Contains(listing, "cert-v01@openssh.com") {
		t.Fatalf("ssh-add -L = %v\n%s", err, listing)
	}
	connected, err := container.exec(t, "ssh", "-F", "/dev/null", "-p", fmt.Sprint(sshPort), "-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "root@127.0.0.1", "echo", "gate-connected")
	if err != nil || !strings.Contains(connected, "gate-connected") {
		t.Fatalf("ssh from the container = %v\n%s", err, connected)
	}

	// A policy change is observed on connections that stay open.
	agentConnection, err := net.Dial("unix", filepath.Join(consumerDirectory, consumer.SSHAgentSocket))
	if err != nil {
		t.Fatal(err)
	}
	defer agentConnection.Close()
	agentClient := agentclient.NewClient(agentConnection)
	if keys, err := agentClient.List(); err != nil || len(keys) != 2 {
		t.Fatalf("identities before the change = %v, %v", keys, err)
	}
	vaultClient := &http.Client{Transport: &http.Transport{MaxIdleConnsPerHost: 1, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", filepath.Join(consumerDirectory, consumer.VaultSocket))
	}}}
	readStatus := func() int {
		response, err := vaultClient.Get("http://localhost/v1/kv/data/teams/teal/example")
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		_, _ = bufio.NewReader(response.Body).WriteTo(&bytes.Buffer{})
		return response.StatusCode
	}
	if status := readStatus(); status != http.StatusOK {
		t.Fatalf("read before the change = %d", status)
	}
	changed := document.Clone()
	changed.OpenBao.Policy = strings.Replace(gateHCL, `path "kv/data/teams/teal/*" { capabilities = ["read"] }`, "", 1)
	changed.SSH.TransitKeys = nil
	if _, err := controller.SavePolicy(ctx, changed, "gate-operator"); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the policy change on open connections", 30*time.Second, func() bool {
		keys, err := agentClient.List()
		return err == nil && len(keys) == 1 && readStatus() == http.StatusForbidden
	})
	if _, err := controller.SavePolicy(ctx, document, "gate-operator"); err != nil {
		t.Fatal(err)
	}

	// The agent restarts without the controller: the directory and sockets
	// are restored from cache before any controller contact, and full
	// service resumes when the controller returns, without touching the
	// container.
	controller.Stop()
	running.stop()
	restarted := startAgent(t, paths, consumerRoot)
	eventually(t, "restored sockets", 30*time.Second, func() bool {
		output, _ := container.exec(t, "sh", "-c", "test -S /run/wyrwood/vault.sock && test -S /run/wyrwood/ssh-agent.sock && echo present")
		return strings.Contains(output, "present")
	})
	unavailable, _ := container.exec(t, "bao", "kv", "get", "kv/teams/teal/example")
	if !strings.Contains(unavailable, "wyrwood") {
		t.Fatalf("read without the controller = %s", unavailable)
	}
	controller = controllertest.StartIn(t, bao, controllerState, controller.SSHAddress)
	eventually(t, "service after the controller returns", 2*time.Minute, func() bool {
		output, err := container.exec(t, "bao", "kv", "get", "-field=value", "kv/teams/teal/example")
		return err == nil && strings.TrimSpace(output) == gateSecret
	})

	// Durable and projected output carries no secret material.
	var status agent.Status
	var listingProjection agent.Containers
	var history agent.Events
	for request, destination := range map[string]any{"status": &status, "containers": &listingProjection, "events": &history} {
		if err := agent.Query(ctx, paths, agent.ControlRequest{Operation: request, Limit: 1000}, destination); err != nil {
			t.Fatal(err)
		}
	}
	projected, _ := json.Marshal([]any{status, listingProjection, history})
	scanForSecrets(t, "control projections", projected)
	for _, directory := range []string{paths.State, controllerState} {
		_ = filepath.Walk(directory, func(path string, info os.FileInfo, err error) error {
			if err == nil && info.Mode().IsRegular() && !strings.HasSuffix(path, "_key") {
				data, _ := os.ReadFile(path)
				scanForSecrets(t, path, data)
			}
			return nil
		})
	}

	// Destroying the container revokes its token.
	liveBefore := bindingTokens(t, bao, "wyrwood-teal")
	if liveBefore == 0 {
		t.Fatal("no live binding token before destroy")
	}
	// Capture the operator's replacement definition before removing the old
	// container. Use the same name, labels, mount source, and environment.
	client := engine.NewClient("/var/run/docker.sock")
	previous, err := client.Inspect(ctx, container.id(t))
	if err != nil {
		t.Fatal(err)
	}
	request, err := contract.BuildCreateRequest(previous, document.Contract, consumerDirectory, previous.Image)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(consumerDirectory)
	if err != nil {
		t.Fatal(err)
	}
	run(t, "docker", "rm", "--force", container.id(t))
	eventually(t, "token revocation after destroy", time.Minute, func() bool { return bindingTokens(t, bao, "wyrwood-teal") == 0 })
	eventually(t, "consumer socket removal", 30*time.Second, func() bool {
		_, err := os.Stat(filepath.Join(consumerDirectory, consumer.VaultSocket))
		return os.IsNotExist(err)
	})
	// Manually create the replacement only after the controller has withdrawn
	// the old match. The consumer directory must still be the mount source.
	after, err := os.Stat(consumerDirectory)
	if err != nil || !os.SameFile(before, after) {
		t.Fatalf("manual recreate lost mount source: %v", err)
	}
	replacementID, err := client.Create(ctx, request.Name, request.Body)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Start(ctx, replacementID); err != nil {
		t.Fatal(err)
	}
	eventually(t, "manual replacement vault socket", time.Minute, func() bool {
		output, err := container.exec(t, "bao", "kv", "get", "-field=value", "kv/teams/teal/example")
		return err == nil && strings.TrimSpace(output) == gateSecret
	})
	eventually(t, "manual replacement ssh socket", time.Minute, func() bool {
		output, err := container.exec(t, "ssh-add", "-L")
		return err == nil && strings.Contains(output, "teal-signing")
	})
	after, err = os.Stat(consumerDirectory)
	if err != nil || !os.SameFile(before, after) {
		t.Fatalf("manual replacement changed mount source: %v", err)
	}
	restarted.stop()
}

var (
	tokenPattern = regexp.MustCompile(`\bs\.[A-Za-z0-9]{24}\b`)
	uuidPattern  = regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
)

func scanForSecrets(t *testing.T, where string, data []byte) {
	t.Helper()
	for _, forbidden := range [][]byte{[]byte(gateSecret), []byte(gateEnvValue), []byte(baotest.RootToken)} {
		if bytes.Contains(data, forbidden) {
			t.Errorf("%s contains %q", where, forbidden)
		}
	}
	if match := tokenPattern.Find(data); match != nil {
		t.Errorf("%s contains a token-shaped value", where)
	}
	if match := uuidPattern.Find(data); match != nil {
		t.Errorf("%s contains a secret-identifier-shaped value", where)
	}
}

// bindingTokens counts live tokens that carry policyName.
func bindingTokens(t *testing.T, bao *baotest.Server, policyName string) int {
	t.Helper()
	listing, err := bao.Root.Logical().List("auth/token/accessors")
	if err != nil || listing == nil {
		t.Fatalf("list accessors = %v", err)
	}
	count := 0
	for _, accessor := range listing.Data["keys"].([]any) {
		secret, err := bao.Root.Logical().Write("auth/token/lookup-accessor", map[string]any{"accessor": accessor})
		if err != nil || secret == nil {
			continue
		}
		for _, name := range secret.Data["policies"].([]any) {
			if name == policyName {
				count++
			}
		}
	}
	return count
}
