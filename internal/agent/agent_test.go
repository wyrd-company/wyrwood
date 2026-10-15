// ---
// relationships:
//   verifies:
//     - agent
//     - container-contract
// ---

package agent

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"
	_ "modernc.org/sqlite"

	"github.com/wyrd-company/wyrwood/internal/binding"
	"github.com/wyrd-company/wyrwood/internal/config"
	"github.com/wyrd-company/wyrwood/internal/consumer"
	"github.com/wyrd-company/wyrwood/internal/controller/controllertest"
	"github.com/wyrd-company/wyrwood/internal/engine"
	"github.com/wyrd-company/wyrwood/internal/engine/enginetest"
	"github.com/wyrd-company/wyrwood/internal/events"
	"github.com/wyrd-company/wyrwood/internal/openbao"
	"github.com/wyrd-company/wyrwood/internal/openbao/baotest"
	"github.com/wyrd-company/wyrwood/internal/policy"
	"github.com/wyrd-company/wyrwood/internal/protocol"
)

// probeEndpoints answers each connection with the binding it sees.
type probeEndpoints struct{}

func (probeEndpoints) ServeVault(listener net.Listener, lookup binding.Lookup, _ binding.Recorder) {
	serveProbe(listener, lookup)
}

func (probeEndpoints) ServeSSHAgent(listener net.Listener, lookup binding.Lookup, _ binding.Recorder) {
	serveProbe(listener, lookup)
}

func serveProbe(listener net.Listener, lookup binding.Lookup) {
	for {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		view, ok := lookup()
		if !ok {
			_, _ = fmt.Fprintln(connection, "unbound")
		} else {
			_, _ = fmt.Fprintf(connection, "%s %t %s\n", view.Policy.Name, view.HasToken, view.Token.Value())
		}
		_ = connection.Close()
	}
}

func probe(t *testing.T, path string) string {
	t.Helper()
	connection, err := net.Dial("unix", path)
	if err != nil {
		return "unreachable"
	}
	defer connection.Close()
	line, _ := bufio.NewReader(connection).ReadString('\n')
	return strings.TrimSpace(line)
}

func eventually(t *testing.T, what string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

type testAgent struct {
	paths   Paths
	options Options
	cancel  context.CancelFunc
	done    chan error
	agent   *Agent
}

func newPaths(t *testing.T) Paths {
	base := t.TempDir()
	return Paths{Config: filepath.Join(base, "etc", "agent.yml"), State: filepath.Join(base, "state"), Runtime: filepath.Join(base, "run")}
}

func startAgent(t *testing.T, paths Paths, fake engine.Engine, allowRecreate bool) *testAgent {
	t.Helper()
	configuration, err := config.LoadAgent(paths.Config)
	if err != nil {
		t.Fatal(err)
	}
	configuration.ConsumerRoot = filepath.Join(paths.Runtime, "containers")
	configuration.AllowRecreate = allowRecreate
	configuration.ControllerTimeout = 2 * time.Second
	options := Options{Config: configuration, Paths: paths, Engine: fake, Endpoints: probeEndpoints{}, Hostname: "host-a",
		CanAssign: func(uint32) bool { return true }}
	instance, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	running := &testAgent{paths: paths, options: options, cancel: cancel, done: make(chan error, 1), agent: instance}
	go func() { running.done <- instance.Run(ctx) }()
	t.Cleanup(running.stop)
	return running
}

func (running *testAgent) stop() {
	if running.cancel == nil {
		return
	}
	running.cancel()
	<-running.done
	running.cancel = nil
}

func login(t *testing.T, paths Paths, controllerURL, fingerprint string) LoginResult {
	t.Helper()
	result, err := Login(context.Background(), LoginOptions{
		Paths: paths, ControllerURL: controllerURL, AcceptFingerprint: fingerprint,
		Hostname: func() (string, error) { return "host-a", nil },
	})
	if err != nil {
		t.Fatalf("Login() = %v", err)
	}
	return result
}

func TestLoginPinsTheControllerAndReportsApproval(t *testing.T) {
	ctx := context.Background()
	bao := baotest.Start(t)
	controller := controllertest.Start(t, bao)
	paths := newPaths(t)

	_, err := Login(ctx, LoginOptions{Paths: paths, ControllerURL: controller.URL, AcceptFingerprint: "SHA256:wrong",
		Hostname: func() (string, error) { return "host-a", nil }})
	if !errors.Is(err, ErrHostKeyMismatch) {
		t.Fatalf("Login(wrong fingerprint) = %v", err)
	}
	_, err = Login(ctx, LoginOptions{Paths: paths, ControllerURL: controller.URL, Confirm: func(string) bool { return false },
		Hostname: func() (string, error) { return "host-a", nil }})
	if !errors.Is(err, ErrNotAccepted) {
		t.Fatalf("Login(declined) = %v", err)
	}
	var confirmed string
	result, err := Login(ctx, LoginOptions{Paths: paths, ControllerURL: controller.URL,
		Confirm:  func(fingerprint string) bool { confirmed = fingerprint; return true },
		Hostname: func() (string, error) { return "host-a", nil }})
	if err != nil || result.Approved || confirmed != controller.Fingerprint || result.ControllerFingerprint != controller.Fingerprint {
		t.Fatalf("Login(pending) = %#v, %v", result, err)
	}
	keyInfo, err := os.Stat(paths.AgentKey())
	if err != nil || keyInfo.Mode().Perm() != 0o600 {
		t.Fatalf("agent key mode = %v, %v", keyInfo, err)
	}
	if err := controller.DecideAgent(ctx, result.AgentFingerprint, true, "operator-1"); err != nil {
		t.Fatal(err)
	}
	approved := login(t, paths, controller.URL, "")
	if !approved.Approved || approved.AgentFingerprint != result.AgentFingerprint {
		t.Fatalf("Login(approved) = %#v", approved)
	}
	configuration, err := config.LoadAgent(paths.Config)
	if err != nil || configuration.ControllerURL != controller.URL {
		t.Fatalf("agent configuration = %#v, %v", configuration, err)
	}
	if _, err := Login(ctx, LoginOptions{Paths: paths, ControllerURL: "ssh://127.0.0.1:1",
		AcceptFingerprint: controller.Fingerprint, Hostname: func() (string, error) { return "host-a", nil }}); !errors.Is(err, ErrUnreachable) {
		t.Fatalf("Login(unreachable) = %v", err)
	}
}

func TestAgentBindsServesAndRetires(t *testing.T) {
	ctx := context.Background()
	bao := baotest.Start(t)
	controller := controllertest.Start(t, bao)
	paths := newPaths(t)
	first := login(t, paths, controller.URL, controller.Fingerprint)
	if err := controller.DecideAgent(ctx, first.AgentFingerprint, true, "operator-1"); err != nil {
		t.Fatal(err)
	}

	fake := enginetest.New()
	web := engine.Container{Name: "/web"}
	web.State.Status = "running"
	web.Config.Image = "example/web:1"
	web.Config.Env = []string{"SECRET_VALUE=hidden"}
	fake.Add(web)
	running := startAgent(t, paths, fake, false)
	eventually(t, "inventory at the controller", func() bool {
		containers, _, _ := controller.Store().Inventory(ctx, "host-a")
		return len(containers) == 1
	})
	containers, _, _ := controller.Store().Inventory(ctx, "host-a")
	if len(containers[0].EnvNames) != 1 || containers[0].EnvNames[0] != "SECRET_VALUE" {
		t.Fatalf("inventory environment = %#v", containers[0].EnvNames)
	}

	document := policy.New("teal", `path "kv/data/teams/teal/*" { capabilities = ["read"] }`)
	if _, err := controller.SavePolicy(ctx, document, "operator-1"); err != nil {
		t.Fatal(err)
	}
	bound, err := controller.CreateBinding(ctx, "host-a", protocol.Key{Kind: protocol.KeyName, Value: "web"}, "teal", "operator-1")
	if err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(paths.Runtime, "containers", "web", "vault.sock")
	var token string
	eventually(t, "a bound socket with a token", func() bool {
		fields := strings.Fields(probe(t, socket))
		if len(fields) == 3 && fields[0] == "teal" && fields[1] == "true" {
			token = fields[2]
			return true
		}
		return false
	})
	reader, _ := openbao.NewClient(openbao.Endpoint{Address: bao.Address, Namespace: bao.Namespace})
	reader.SetToken(token)
	if _, err := reader.Auth().Token().LookupSelf(); err != nil {
		t.Fatalf("agent token does not work: %v", err)
	}
	eventually(t, "a non-conforming contract result", func() bool {
		results, _ := controller.Store().ContractResults(ctx)
		return results[bound.ID].Outcome == protocol.OutcomeNonConforming
	})

	var status Status
	if err := Query(ctx, paths, ControlRequest{Operation: "status"}, &status); err != nil {
		t.Fatal(err)
	}
	if status.Session != "connected" || status.Bindings != 1 || status.Tokens != 1 || status.Agent != "host-a" {
		t.Fatalf("status = %#v", status)
	}
	var listing Containers
	if err := Query(ctx, paths, ControlRequest{Operation: "containers"}, &listing); err != nil {
		t.Fatal(err)
	}
	if len(listing.Containers) != 1 || listing.Containers[0].Policy != "teal" || listing.Containers[0].Token != "valid" ||
		listing.Containers[0].BindingKey != "name:web" || listing.Containers[0].Conformance != "non-conforming" {
		t.Fatalf("containers = %#v", listing)
	}

	// The agent keeps serving from cache across a restart without the controller.
	controller.Stop()
	running.stop()
	restarted := startAgent(t, paths, fake, false)
	eventually(t, "restored socket", func() bool { return strings.HasPrefix(probe(t, socket), "teal ") })
	if fields := strings.Fields(probe(t, socket)); fields[1] != "false" {
		t.Fatalf("restarted agent claims a token: %v", fields)
	}
	restarted.stop()

	controller = controllertest.StartIn(t, bao, filepath.Dir(filepath.Dir(controllerStateHint(t, controller))), controller.SSHAddress)
	_ = startAgent(t, paths, fake, false)
	eventually(t, "a fresh token after reconnect", func() bool {
		fields := strings.Fields(probe(t, socket))
		return len(fields) == 3 && fields[1] == "true"
	})
	fields := strings.Fields(probe(t, socket))
	token = fields[2]

	// Destroying the container revokes its token and removes the sockets.
	fake.Destroy(func() string { container, _ := fake.ByName("web"); return container.ID }())
	eventually(t, "consumer socket removal", func() bool {
		_, err := os.Stat(socket)
		return os.IsNotExist(err)
	})
	reader.SetToken(token)
	eventually(t, "token revocation", func() bool {
		_, err := reader.Auth().Token().LookupSelf()
		return err != nil
	})
	// The stored name binding survives the gap; the replacement reuses the
	// directory the original container would have mounted.
	before, err := os.Stat(filepath.Dir(socket))
	if err != nil {
		t.Fatalf("retained mount source: %v", err)
	}
	fake.Add(web)
	eventually(t, "replacement sockets with a fresh token", func() bool {
		for _, name := range []string{consumer.VaultSocket, consumer.SSHAgentSocket} {
			fields := strings.Fields(probe(t, filepath.Join(filepath.Dir(socket), name)))
			if len(fields) != 3 || fields[0] != "teal" || fields[1] != "true" || fields[2] == token {
				return false
			}
		}
		return true
	})
	after, err := os.Stat(filepath.Dir(socket))
	if err != nil || !os.SameFile(before, after) {
		t.Fatalf("manual recreate replaced mount source: %v", err)
	}
	var history Events
	if err := Query(ctx, paths, ControlRequest{Operation: "events", Limit: 1000}, &history); err != nil {
		t.Fatal(err)
	}
	seen := map[events.Operation]bool{}
	for _, record := range history.Events {
		seen[record.Operation] = true
	}
	for _, operation := range []events.Operation{events.OperationContainerObserved, events.OperationBindingReceived,
		events.OperationLogin, events.OperationContractChecked, events.OperationContainerGone, events.OperationRevoke, events.OperationBindingRetired} {
		if !seen[operation] {
			t.Errorf("no %s event", operation)
		}
	}
	assertNoSecrets(t, paths, token)
}

// controllerStateHint recovers the controller state directory from its host key.
func controllerStateHint(t *testing.T, controller *controllertest.Controller) string {
	t.Helper()
	return controller.Configuration().StateDirectory + "/ssh/key"
}

func TestRecreateOnNewBindingAndUnbind(t *testing.T) {
	ctx := context.Background()
	bao := baotest.Start(t)
	controller := controllertest.Start(t, bao)
	paths := newPaths(t)
	first := login(t, paths, controller.URL, controller.Fingerprint)
	if err := controller.DecideAgent(ctx, first.AgentFingerprint, true, "operator-1"); err != nil {
		t.Fatal(err)
	}
	fake := enginetest.New()
	app := engine.Container{Name: "/app"}
	app.State.Status = "running"
	app.Config.Labels = map[string]string{"devcontainer.local_folder": "/src/app"}
	fake.Add(app)
	startAgent(t, paths, fake, true)
	eventually(t, "inventory", func() bool {
		containers, _, _ := controller.Store().Inventory(ctx, "host-a")
		return len(containers) == 1
	})
	document := policy.New("recreate", `path "kv/data/app/*" { capabilities = ["read"] }`)
	document.Contract.Enforcement = policy.EnforcementRecreate
	if _, err := controller.SavePolicy(ctx, document, "operator-1"); err != nil {
		t.Fatal(err)
	}
	bound, err := controller.CreateBinding(ctx, "host-a", protocol.Key{Kind: protocol.KeyDevcontainer, Value: "/src/app"}, "recreate", "operator-1")
	if err != nil {
		t.Fatal(err)
	}
	eventually(t, "recreated result", func() bool {
		results, _ := controller.Store().ContractResults(ctx)
		return results[bound.ID].Outcome == protocol.OutcomeConforming
	})
	if calls := strings.Join(fake.CallLog(), ","); calls != "stop,remove,create,start" {
		t.Fatalf("engine calls = %s", calls)
	}
	recreated, ok := fake.ByName("app")
	if !ok || recreated.Config.Labels["devcontainer.local_folder"] != "/src/app" {
		t.Fatalf("recreated container = %#v", recreated)
	}
	// A later reconcile reports drift instead of recreating again.
	if err := controller.RequestRecreate(ctx, bound.ID, "operator-1"); err != nil {
		t.Fatal(err)
	}
	eventually(t, "explicit recreate", func() bool { return len(fake.CallLog()) == 8 })

	if err := controller.DeleteBinding(ctx, bound.ID, "operator-1"); err != nil {
		t.Fatal(err)
	}
	eventually(t, "unbound socket removal", func() bool {
		_, err := os.Stat(filepath.Join(paths.Runtime, "containers", "app", consumer.VaultSocket))
		return os.IsNotExist(err)
	})
}

func TestInterruptionReportReachesTheController(t *testing.T) {
	ctx := context.Background()
	bao := baotest.Start(t)
	controller := controllertest.Start(t, bao)
	paths := newPaths(t)
	first := login(t, paths, controller.URL, controller.Fingerprint)
	if err := controller.DecideAgent(ctx, first.AgentFingerprint, true, "operator-1"); err != nil {
		t.Fatal(err)
	}
	document := policy.New("recreate", `path "kv/data/app/*" { capabilities = ["read"] }`)
	document.Contract.Enforcement = policy.EnforcementRecreate
	if _, err := controller.SavePolicy(ctx, document, "operator-1"); err != nil {
		t.Fatal(err)
	}
	key := protocol.Key{Kind: protocol.KeyName, Value: "app"}
	bound, err := controller.CreateBinding(ctx, "host-a", key, "recreate", "operator-1")
	if err != nil {
		t.Fatal(err)
	}
	// An earlier agent process stopped app and exited before creating it.
	journal, _ := json.Marshal(recreateJournal{Version: 1, Binding: bound.ID, Key: key})
	if err := writeOwnerOnly(paths.RecreateJournal("app"), journal, false); err != nil {
		t.Fatal(err)
	}
	startAgent(t, paths, enginetest.New(), true)
	eventually(t, "recreate-failed at the controller", func() bool {
		results, _ := controller.Store().ContractResults(ctx)
		return results[bound.ID].Outcome == protocol.OutcomeRecreateFailed
	})
	eventually(t, "journal removal after delivery", func() bool {
		_, err := os.Stat(paths.RecreateJournal("app"))
		return os.IsNotExist(err)
	})
}

func TestInterruptionReportSurvivesAControllerStorageFailure(t *testing.T) {
	ctx := context.Background()
	bao := baotest.Start(t)
	state := t.TempDir()
	controller := controllertest.StartIn(t, bao, state, controllertest.FreeAddress(t))
	paths := newPaths(t)
	first := login(t, paths, controller.URL, controller.Fingerprint)
	if err := controller.DecideAgent(ctx, first.AgentFingerprint, true, "operator-1"); err != nil {
		t.Fatal(err)
	}
	document := policy.New("recreate", `path "kv/data/app/*" { capabilities = ["read"] }`)
	document.Contract.Enforcement = policy.EnforcementRecreate
	if _, err := controller.SavePolicy(ctx, document, "operator-1"); err != nil {
		t.Fatal(err)
	}
	key := protocol.Key{Kind: protocol.KeyName, Value: "app"}
	bound, err := controller.CreateBinding(ctx, "host-a", key, "recreate", "operator-1")
	if err != nil {
		t.Fatal(err)
	}
	journal, _ := json.Marshal(recreateJournal{Version: 1, Binding: bound.ID, Key: key})
	if err := writeOwnerOnly(paths.RecreateJournal("app"), journal, false); err != nil {
		t.Fatal(err)
	}
	// The controller's storage refuses every contract result.
	database, err := sql.Open("sqlite", "file:"+filepath.Join(state, "controller.db")+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	for _, statement := range []string{
		`CREATE TRIGGER refuse_insert BEFORE INSERT ON contract_results BEGIN SELECT RAISE(ABORT, 'refused'); END`,
		`CREATE TRIGGER refuse_update BEFORE UPDATE ON contract_results BEGIN SELECT RAISE(ABORT, 'refused'); END`,
	} {
		if _, err := database.ExecContext(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	running := startAgent(t, paths, enginetest.New(), true)
	eventually(t, "the agent's inventory", func() bool {
		agents, _ := controller.Store().Agents(ctx)
		for _, agent := range agents {
			if agent.Name == "host-a" && !agent.LastReport.IsZero() {
				return true
			}
		}
		return false
	})
	time.Sleep(500 * time.Millisecond)
	if _, err := os.Stat(paths.RecreateJournal("app")); err != nil {
		t.Fatalf("journal after the controller failed to store the report: %v", err)
	}
	running.stop()
	for _, statement := range []string{`DROP TRIGGER refuse_insert`, `DROP TRIGGER refuse_update`} {
		if _, err := database.ExecContext(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	startAgent(t, paths, enginetest.New(), true)
	eventually(t, "recreate-failed at the controller after the restart", func() bool {
		results, _ := controller.Store().ContractResults(ctx)
		return results[bound.ID].Outcome == protocol.OutcomeRecreateFailed
	})
	eventually(t, "journal removal after the controller recorded the report", func() bool {
		_, err := os.Stat(paths.RecreateJournal("app"))
		return os.IsNotExist(err)
	})
}

func TestUnbindingRevokesTheTokenOfADisconnectedAgent(t *testing.T) {
	ctx := context.Background()
	bao := baotest.Start(t)
	bao.WriteKV(t, "app/example", map[string]any{"value": "app-secret"})
	state := t.TempDir()
	first := controllertest.StartIn(t, bao, state, controllertest.FreeAddress(t))
	paths := newPaths(t)
	login := login(t, paths, first.URL, first.Fingerprint)
	if err := first.DecideAgent(ctx, login.AgentFingerprint, true, "operator-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := first.SavePolicy(ctx, policy.New("app", `path "kv/data/app/*" { capabilities = ["read"] }`), "operator-1"); err != nil {
		t.Fatal(err)
	}
	fake := enginetest.New()
	app := engine.Container{Name: "/app"}
	app.State.Status = "running"
	fake.Add(app)
	running := startAgent(t, paths, fake, false)
	bound, err := first.CreateBinding(ctx, "host-a", protocol.Key{Kind: protocol.KeyName, Value: "app"}, "app", "operator-1")
	if err != nil {
		t.Fatal(err)
	}
	var token openbao.Token
	eventually(t, "a token whose accessor the controller recorded", func() bool {
		held, ok := running.agent.creds.current(bound.ID)
		recorded, err := first.Store().TokenAccessor(ctx, bound.ID)
		token = held
		return ok && err == nil && recorded == held.Accessor
	})
	readSecret := func() error {
		client, err := bao.Root.CloneWithHeaders()
		if err != nil {
			t.Fatal(err)
		}
		client.SetToken(token.Value())
		_, err = client.Logical().Read("kv/data/app/example")
		return err
	}
	if err := readSecret(); err != nil {
		t.Fatalf("the binding's token cannot read its secret before the deletion: %v", err)
	}
	// The agent keeps running and keeps its token, but the controller it
	// knows is gone; a controller on the same state at another address
	// deletes the binding.
	first.Stop()
	second := controllertest.StartIn(t, bao, state, controllertest.FreeAddress(t))
	if err := second.DeleteBinding(ctx, bound.ID, "operator-1"); err != nil {
		t.Fatalf("DeleteBinding(disconnected agent with a reported token) = %v", err)
	}
	if _, ok := running.agent.creds.current(bound.ID); !ok {
		t.Fatal("the agent dropped its token on its own; the test proves nothing")
	}
	if err := readSecret(); err == nil {
		t.Fatal("the deleted binding's token still reads its secret")
	}
}

func TestAccessorReportSurvivesAControllerStorageFailure(t *testing.T) {
	ctx := context.Background()
	bao := baotest.Start(t)
	bao.WriteKV(t, "app/example", map[string]any{"value": "app-secret"})
	state := t.TempDir()
	first := controllertest.StartIn(t, bao, state, controllertest.FreeAddress(t))
	paths := newPaths(t)
	login := login(t, paths, first.URL, first.Fingerprint)
	if err := first.DecideAgent(ctx, login.AgentFingerprint, true, "operator-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := first.SavePolicy(ctx, policy.New("app", `path "kv/data/app/*" { capabilities = ["read"] }`), "operator-1"); err != nil {
		t.Fatal(err)
	}
	// The controller's storage refuses every token accessor write.
	database, err := sql.Open("sqlite", "file:"+filepath.Join(state, "controller.db")+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	for _, statement := range []string{
		`CREATE TRIGGER refuse_insert BEFORE INSERT ON binding_tokens BEGIN SELECT RAISE(ABORT, 'refused'); END`,
		`CREATE TRIGGER refuse_update BEFORE UPDATE ON binding_tokens BEGIN SELECT RAISE(ABORT, 'refused'); END`,
	} {
		if _, err := database.ExecContext(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	fake := enginetest.New()
	app := engine.Container{Name: "/app"}
	app.State.Status = "running"
	fake.Add(app)
	running := startAgent(t, paths, fake, false)
	bound, err := first.CreateBinding(ctx, "host-a", protocol.Key{Kind: protocol.KeyName, Value: "app"}, "app", "operator-1")
	if err != nil {
		t.Fatal(err)
	}
	var token openbao.Token
	eventually(t, "a token", func() bool {
		held, ok := running.agent.creds.current(bound.ID)
		token = held
		return ok
	})
	time.Sleep(500 * time.Millisecond)
	if _, err := first.Store().TokenAccessor(ctx, bound.ID); err == nil {
		t.Fatal("an accessor was recorded while storage refused it")
	}
	for _, statement := range []string{`DROP TRIGGER refuse_insert`, `DROP TRIGGER refuse_update`} {
		if _, err := database.ExecContext(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	// The next reconcile sends the unacknowledged report again.
	if err := running.agent.fullReconcile(ctx); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the accessor recorded after storage recovered", func() bool {
		recorded, err := first.Store().TokenAccessor(ctx, bound.ID)
		return err == nil && recorded == token.Accessor
	})
	first.Stop()
	second := controllertest.StartIn(t, bao, state, controllertest.FreeAddress(t))
	if err := second.DeleteBinding(ctx, bound.ID, "operator-1"); err != nil {
		t.Fatalf("DeleteBinding(disconnected agent) = %v", err)
	}
	if _, ok := running.agent.creds.current(bound.ID); !ok {
		t.Fatal("the agent dropped its token on its own; the test proves nothing")
	}
	client, err := bao.Root.CloneWithHeaders()
	if err != nil {
		t.Fatal(err)
	}
	client.SetToken(token.Value())
	if _, err := client.Logical().Read("kv/data/app/example"); err == nil {
		t.Fatal("the deleted binding's token still reads its secret")
	}
}

func TestRecreateNotAllowedIsReported(t *testing.T) {
	ctx := context.Background()
	bao := baotest.Start(t)
	controller := controllertest.Start(t, bao)
	paths := newPaths(t)
	first := login(t, paths, controller.URL, controller.Fingerprint)
	_ = controller.DecideAgent(ctx, first.AgentFingerprint, true, "operator-1")
	fake := enginetest.New()
	app := engine.Container{Name: "/app"}
	app.State.Status = "running"
	fake.Add(app)
	startAgent(t, paths, fake, false)
	document := policy.New("recreate", `path "kv/data/app/*" { capabilities = ["read"] }`)
	document.Contract.Enforcement = policy.EnforcementRecreate
	if _, err := controller.SavePolicy(ctx, document, "operator-1"); err != nil {
		t.Fatal(err)
	}
	eventually(t, "inventory", func() bool {
		containers, _, _ := controller.Store().Inventory(ctx, "host-a")
		return len(containers) == 1
	})
	bound, err := controller.CreateBinding(ctx, "host-a", protocol.Key{Kind: protocol.KeyName, Value: "app"}, "recreate", "operator-1")
	if err != nil {
		t.Fatal(err)
	}
	eventually(t, "recreate-not-allowed", func() bool {
		results, _ := controller.Store().ContractResults(ctx)
		for _, item := range results[bound.ID].FailedItems {
			if item == protocol.FailedRecreateNotAllowed {
				return true
			}
		}
		return false
	})
	if calls := fake.CallLog(); len(calls) != 0 {
		t.Fatalf("engine writes without permission: %v", calls)
	}
}

func TestHostKeyMismatchRefusesToConnect(t *testing.T) {
	bao := baotest.Start(t)
	controller := controllertest.Start(t, bao)
	paths := newPaths(t)
	login(t, paths, controller.URL, controller.Fingerprint)
	if err := SaveKnownController(paths, KnownControllerRecord{URL: controller.URL, Fingerprint: "SHA256:" + strings.Repeat("A", 43)}); err != nil {
		t.Fatal(err)
	}
	configuration, _ := config.LoadAgent(paths.Config)
	configuration.ConsumerRoot = filepath.Join(paths.Runtime, "containers")
	instance, err := New(Options{Config: configuration, Paths: paths, Engine: enginetest.New(), Hostname: "host-a"})
	if err != nil {
		t.Fatal(err)
	}
	defer instance.shutdown()
	if _, err := instance.connectOnce(context.Background()); !errors.Is(err, errHostKey) {
		t.Fatalf("connectOnce() = %v, want host-key mismatch", err)
	}
}

func TestKeysFollowPrecedence(t *testing.T) {
	container := engine.Container{Name: "/shop-web-1"}
	container.Config.Labels = map[string]string{
		"devcontainer.local_folder": "/src/shop", "devcontainer.config_file": "/src/shop/.devcontainer/devcontainer.json",
		"com.docker.compose.project": "shop", "com.docker.compose.service": "web",
	}
	keys := Keys(container)
	want := []protocol.Key{
		{Kind: protocol.KeyDevcontainer, Value: "/src/shop|/src/shop/.devcontainer/devcontainer.json"},
		{Kind: protocol.KeyCompose, Value: "shop/web"},
		{Kind: protocol.KeyName, Value: "shop-web-1"},
	}
	if fmt.Sprint(keys) != fmt.Sprint(want) {
		t.Fatalf("Keys() = %v", keys)
	}
}

// assertNoSecrets scans durable agent state for a token value.
func assertNoSecrets(t *testing.T, paths Paths, secrets ...string) {
	t.Helper()
	_ = filepath.Walk(paths.State, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		data, _ := os.ReadFile(path)
		for _, secret := range secrets {
			if secret != "" && strings.Contains(string(data), secret) {
				t.Errorf("%s contains a secret", path)
			}
		}
		if strings.Contains(string(data), "hidden") && !strings.HasSuffix(path, "agent_key") {
			t.Errorf("%s contains an environment value", path)
		}
		return nil
	})
	if _, err := os.Stat(paths.KnownController()); err != nil {
		t.Fatal(err)
	}
	_ = gossh.FingerprintSHA256
}
