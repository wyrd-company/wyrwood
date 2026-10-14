// ---
// relationships:
//   verifies:
//     - controller
//     - agent-controller-protocol
// ---

package controller

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/openbao/openbao/api/v2"
	gossh "golang.org/x/crypto/ssh"

	"github.com/wyrd-company/wyrwood/internal/config"
	"github.com/wyrd-company/wyrwood/internal/controller/store"
	"github.com/wyrd-company/wyrwood/internal/events"
	"github.com/wyrd-company/wyrwood/internal/openbao"
	"github.com/wyrd-company/wyrwood/internal/openbao/baotest"
	"github.com/wyrd-company/wyrwood/internal/policy"
	"github.com/wyrd-company/wyrwood/internal/protocol"
)

type harness struct {
	controller *Controller
	bao        *baotest.Server
	address    string
	hostKey    gossh.PublicKey
}

func freeAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	return address
}

func startHarness(t *testing.T) *harness {
	t.Helper()
	bao := baotest.Start(t)
	roleID, secretFile := bao.ControllerCredentials(t)
	state := t.TempDir()
	configuration := config.Controller{
		HTTPListen: freeAddress(t), SSHListen: freeAddress(t), StateDirectory: state, SessionTTL: time.Hour,
		OpenBao: config.ControllerOpenBao{Address: bao.Address, AppRoleMount: "approle", RoleID: roleID,
			SecretIDFile: secretFile, TransitMount: "transit", SSHMount: "ssh"},
	}
	controller, err := New(configuration, Options{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- controller.Run(ctx, nil) }()
	t.Cleanup(func() {
		cancel()
		<-done
		_ = controller.Close()
	})
	deadline := time.Now().Add(10 * time.Second)
	for {
		connection, err := net.Dial("tcp", configuration.SSHListen)
		if err == nil {
			_ = connection.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("controller SSH server did not start")
		}
		time.Sleep(50 * time.Millisecond)
	}
	fingerprint, err := HostKeyFingerprint(state)
	if err != nil || !strings.HasPrefix(fingerprint, "SHA256:") {
		t.Fatalf("HostKeyFingerprint() = %q, %v", fingerprint, err)
	}
	signer, err := LoadOrCreateHostKey(state)
	if err != nil {
		t.Fatal(err)
	}
	return &harness{controller: controller, bao: bao, address: configuration.SSHListen, hostKey: signer.PublicKey()}
}

func newAgentKey(t *testing.T) gossh.Signer {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := gossh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

type agentConnection struct {
	client *gossh.Client
	conn   *protocol.Conn
}

func (harness *harness) dial(name string, key gossh.Signer) (*agentConnection, error) {
	client, err := gossh.Dial("tcp", harness.address, &gossh.ClientConfig{
		User: name, Auth: []gossh.AuthMethod{gossh.PublicKeys(key)},
		HostKeyCallback: gossh.FixedHostKey(harness.hostKey), Timeout: 5 * time.Second,
	})
	if err != nil {
		return nil, err
	}
	session, err := client.NewSession()
	if err != nil {
		_ = client.Close()
		return nil, err
	}
	stdin, _ := session.StdinPipe()
	stdout, _ := session.StdoutPipe()
	if err := session.RequestSubsystem(protocol.SubsystemName); err != nil {
		_ = client.Close()
		return nil, err
	}
	return &agentConnection{client: client, conn: protocol.NewConn(struct {
		readerFrom
		writerTo
	}{readerFrom{stdout}, writerTo{stdin}})}, nil
}

type readerFrom struct {
	r interface{ Read([]byte) (int, error) }
}

func (reader readerFrom) Read(data []byte) (int, error) { return reader.r.Read(data) }

type writerTo struct {
	w interface{ Write([]byte) (int, error) }
}

func (writer writerTo) Write(data []byte) (int, error) { return writer.w.Write(data) }

func (connection *agentConnection) receive(t *testing.T) protocol.Message {
	t.Helper()
	type result struct {
		message protocol.Message
		err     error
	}
	received := make(chan result, 1)
	go func() {
		message, err := connection.conn.Receive()
		received <- result{message, err}
	}()
	select {
	case outcome := <-received:
		if outcome.err != nil {
			t.Fatalf("Receive() = %v", outcome.err)
		}
		return outcome.message
	case <-time.After(10 * time.Second):
		t.Fatal("Receive() timed out")
	}
	return nil
}

func TestEnrollmentBindingAndCredentialIssuance(t *testing.T) {
	ctx := context.Background()
	harness := startHarness(t)
	controller := harness.controller
	key := newAgentKey(t)

	if _, err := harness.dial("host-a", key); err == nil {
		t.Fatal("unapproved key authenticated")
	}
	unknown := newAgentKey(t)
	_, unknownErr := harness.dial("host-b", unknown)
	_, pendingErr := harness.dial("host-a", key)
	if unknownErr == nil || pendingErr == nil || unknownErr.Error() != pendingErr.Error() {
		t.Fatalf("pending and unknown failures differ: %v / %v", unknownErr, pendingErr)
	}
	fingerprint := gossh.FingerprintSHA256(key.PublicKey())
	agent, err := controller.Store().Agent(ctx, fingerprint)
	if err != nil || agent.State != store.AgentPending || agent.Name != "host-a" {
		t.Fatalf("pending agent = %#v, %v", agent, err)
	}
	if err := controller.DecideAgent(ctx, fingerprint, true, "operator-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := harness.dial("other-name", key); err == nil {
		t.Fatal("approved key authenticated under another name")
	}

	connection, err := harness.dial("host-a", key)
	if err != nil {
		t.Fatalf("approved dial = %v", err)
	}
	defer connection.client.Close()
	if err := connection.conn.Send(protocol.Hello{AgentVersion: "test", AllowRecreate: true}); err != nil {
		t.Fatal(err)
	}
	containerID := strings.Repeat("c", 64)
	inventory := protocol.Inventory{Containers: []protocol.Container{{
		ID: containerID, Name: "web", State: protocol.StateRunning,
		Keys: []protocol.Key{{Kind: protocol.KeyCompose, Value: "shop/web"}, {Kind: protocol.KeyName, Value: "web"}},
	}}}
	if err := connection.conn.Send(inventory); err != nil {
		t.Fatal(err)
	}
	if set, ok := connection.receive(t).(protocol.PolicySet); !ok || len(set.Bindings) != 0 || set.OpenBao.Address != harness.bao.Address {
		t.Fatalf("initial policy set = %#v", set)
	}

	document := policy.New("teal", `path "kv/data/teams/teal/*" { capabilities = ["read"] }`)
	document.SSH = &policy.SSH{TransitKeys: []string{"missing-key"}}
	if _, err := controller.SavePolicy(ctx, document, "operator-1"); err == nil || !strings.Contains(err.Error(), "missing-key") {
		t.Fatalf("SavePolicy(missing key) = %v", err)
	}
	broken := policy.New("broken", `path "kv/*" { capabilities = [`)
	if _, err := controller.SavePolicy(ctx, broken, "operator-1"); err == nil {
		t.Fatal("SavePolicy(invalid HCL) = nil")
	}
	document.SSH = nil
	saved, err := controller.SavePolicy(ctx, document, "operator-1")
	if err != nil || saved.Revision != 1 {
		t.Fatalf("SavePolicy() = %#v, %v", saved, err)
	}
	binding, err := controller.CreateBinding(ctx, "host-a", protocol.Key{Kind: protocol.KeyName, Value: "web"}, "teal", "operator-1")
	if err != nil {
		t.Fatalf("CreateBinding() = %v", err)
	}
	set, ok := connection.receive(t).(protocol.PolicySet)
	if !ok || len(set.Bindings) != 1 || set.Bindings[0].Binding != binding.ID || set.Bindings[0].Policy.Revision != 1 {
		t.Fatalf("policy set after binding = %#v", set)
	}
	credential, ok := connection.receive(t).(protocol.Credential)
	if !ok || credential.Binding != binding.ID || credential.AppRoleMount != "approle" {
		t.Fatalf("credential = %#v", credential)
	}
	role, err := harness.bao.Root.Logical().Read("auth/approle/role/" + binding.Role)
	if err != nil || role == nil || fmt.Sprint(role.Data["token_max_ttl"]) != "28800" {
		t.Fatalf("binding AppRole token_max_ttl = %v, %v; want the policy's 8h default", role, err)
	}
	client, _ := openbao.NewClient(openbao.Endpoint{Address: harness.bao.Address, Timeout: 5 * time.Second})
	secretID, err := openbao.UnwrapSecretID(ctx, client, credential.WrappedSecretID)
	if err != nil {
		t.Fatalf("UnwrapSecretID() = %v", err)
	}
	token, err := openbao.AppRoleLogin(ctx, client, "approle", credential.RoleID, secretID)
	if err != nil || strings.Join(token.Policies, ",") != "default,wyrwood-teal" {
		t.Fatalf("binding token = %v, %v", token.Policies, err)
	}

	if err := connection.conn.Send(protocol.CredentialRequest{Binding: binding.ID}); err != nil {
		t.Fatal(err)
	}
	if again, ok := connection.receive(t).(protocol.Credential); !ok || again.WrappedSecretID == credential.WrappedSecretID {
		t.Fatalf("credential request = %#v", again)
	}
	conforming := protocol.ContractResult{Binding: binding.ID, Outcome: protocol.OutcomeConforming}
	if err := connection.conn.Send(conforming); err != nil {
		t.Fatal(err)
	}
	if recorded, ok := connection.receive(t).(protocol.ResultRecorded); !ok || recorded != conforming.Acknowledge() {
		t.Fatalf("acknowledgement = %#v", recorded)
	}
	stored, _ := controller.Store().ContractResults(ctx)
	if stored[binding.ID].Outcome != protocol.OutcomeConforming {
		t.Fatal("acknowledged before the result was stored")
	}
	// A result for a binding that no longer exists can never be stored.
	discarded := protocol.ContractResult{Binding: "missing", Outcome: protocol.OutcomeRecreateFailed, Reason: protocol.ReasonCreateFailed}
	if err := connection.conn.Send(discarded); err != nil {
		t.Fatal(err)
	}
	if recorded, ok := connection.receive(t).(protocol.ResultRecorded); !ok || recorded != discarded.Acknowledge() {
		t.Fatalf("acknowledgement of a discarded result = %#v", recorded)
	}

	replacement, err := harness.dial("host-a", key)
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.client.Close()
	if err := replacement.conn.Send(protocol.Hello{AgentVersion: "test"}); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.conn.Receive(); err == nil {
		t.Fatal("replaced session still open")
	}
	if err := replacement.conn.Send(inventory); err != nil {
		t.Fatal(err)
	}
	if set, ok := replacement.receive(t).(protocol.PolicySet); !ok || len(set.Bindings) != 1 {
		t.Fatalf("replacement policy set = %#v", set)
	}
	if _, ok := replacement.receive(t).(protocol.Credential); !ok {
		t.Fatal("replacement session did not receive a credential")
	}
	results, _ := controller.Store().ContractResults(ctx)
	if results[binding.ID].Outcome != protocol.OutcomeConforming {
		t.Fatalf("contract results = %#v", results)
	}

	// The agent reports its token's accessor; one for a binding it does not
	// hold is ignored.
	for _, report := range []protocol.TokenAccessor{
		{Binding: "missing", Accessor: "unreportedaccessor"},
		{Binding: binding.ID, Accessor: token.Accessor},
	} {
		if err := replacement.conn.Send(report); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		recorded, err := controller.Store().TokenAccessor(ctx, binding.ID)
		if err == nil && recorded == token.Accessor {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("recorded accessor = %q, %v", recorded, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := controller.Store().TokenAccessor(ctx, "missing"); err == nil {
		t.Fatal("an accessor for an unknown binding was recorded")
	}
	if !tokenValid(t, harness.bao, token) {
		t.Fatal("the binding token is not valid before the deletion")
	}

	if err := controller.DeleteBinding(ctx, binding.ID, "operator-1"); err != nil {
		t.Fatal(err)
	}
	if unbind, ok := replacement.receive(t).(protocol.Unbind); !ok || unbind.Binding != binding.ID {
		t.Fatalf("unbind = %#v", unbind)
	}
	if tokenValid(t, harness.bao, token) {
		t.Fatal("the deleted binding's token is still valid")
	}
	if _, err := controller.OpenBao().RoleID(ctx, binding.Role); err == nil {
		t.Fatal("deleted binding's AppRole still exists")
	}

	operations := map[events.Operation]bool{}
	for _, event := range controller.Events().Recent(1000) {
		operations[event.Operation] = true
		if event.Operation == events.OperationAgentApproved && event.Operator != "operator-1" {
			t.Fatalf("approval event = %#v", event)
		}
	}
	for _, operation := range []events.Operation{events.OperationAgentApproved, events.OperationSessionOpened,
		events.OperationSessionClosed, events.OperationPolicySaved, events.OperationBindingCreated,
		events.OperationCredentialIssued, events.OperationBindingDeleted} {
		if !operations[operation] {
			t.Errorf("no %s event", operation)
		}
	}
}

func TestUnbindingAnUnreportedTokenOfADisconnectedAgentSaysItStaysValid(t *testing.T) {
	ctx := context.Background()
	harness := startHarness(t)
	controller := harness.controller
	key := newAgentKey(t)
	_, _ = harness.dial("host-a", key)
	if err := controller.DecideAgent(ctx, gossh.FingerprintSHA256(key.PublicKey()), true, "operator-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := controller.SavePolicy(ctx, policy.New("teal", `path "kv/data/teams/teal/*" { capabilities = ["read"] }`), "operator-1"); err != nil {
		t.Fatal(err)
	}
	binding, err := controller.CreateBinding(ctx, "host-a", protocol.Key{Kind: protocol.KeyName, Value: "web"}, "teal", "operator-1")
	if err != nil {
		t.Fatal(err)
	}
	err = controller.DeleteBinding(ctx, binding.ID, "operator-1")
	var operation *OperationError
	if !errors.As(err, &operation) || operation.Code != events.ErrorControllerUnavailable ||
		!strings.Contains(operation.Message, "stays valid") {
		t.Fatalf("DeleteBinding(disconnected agent) = %v", err)
	}
	if _, err := controller.Store().Binding(ctx, binding.ID); err == nil {
		t.Fatal("binding still stored")
	}
	if _, err := controller.OpenBao().RoleID(ctx, binding.Role); err == nil {
		t.Fatal("deleted binding's AppRole still exists")
	}
	recorded := false
	for _, event := range controller.Events().Recent(1000) {
		if event.Operation == events.OperationBindingDeleted {
			recorded = event.ErrorCode == events.ErrorControllerUnavailable
		}
	}
	if !recorded {
		t.Fatal("binding-deleted event does not record the disconnected agent")
	}
}

// tokenValid reports whether token still authenticates to OpenBao.
func tokenValid(t *testing.T, bao *baotest.Server, token openbao.Token) bool {
	t.Helper()
	client, err := bao.Root.Clone()
	if err != nil {
		t.Fatal(err)
	}
	client.SetToken(token.Value())
	_, err = client.Auth().Token().LookupSelf()
	return err == nil
}

func TestUnbindingReportsATokenOpenBaoDidNotRevoke(t *testing.T) {
	ctx := context.Background()
	harness := startHarness(t)
	controller := harness.controller
	key := newAgentKey(t)
	_, _ = harness.dial("host-a", key)
	if err := controller.DecideAgent(ctx, gossh.FingerprintSHA256(key.PublicKey()), true, "operator-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := controller.SavePolicy(ctx, policy.New("teal", `path "kv/data/teams/teal/*" { capabilities = ["read"] }`), "operator-1"); err != nil {
		t.Fatal(err)
	}
	binding, err := controller.CreateBinding(ctx, "host-a", protocol.Key{Kind: protocol.KeyName, Value: "web"}, "teal", "operator-1")
	if err != nil {
		t.Fatal(err)
	}
	issued, err := harness.bao.Root.Auth().Token().Create(&api.TokenCreateRequest{TTL: "1h"})
	if err != nil {
		t.Fatal(err)
	}
	token := openbao.NewToken(issued.Auth.ClientToken, time.Hour)
	if err := controller.Store().SaveTokenAccessor(ctx, binding.ID, issued.Auth.Accessor, time.Now()); err != nil {
		t.Fatal(err)
	}
	// The controller's OpenBao policy no longer allows revocation.
	withdrawn := strings.Replace(baotest.ControllerPolicy, `path "auth/token/revoke-accessor" { capabilities = ["update"] }`, "", 1)
	if withdrawn == baotest.ControllerPolicy {
		t.Fatal("the controller policy does not grant revoke-accessor")
	}
	if err := harness.bao.Root.Sys().PutPolicy("wyrwood-controller", withdrawn); err != nil {
		t.Fatal(err)
	}
	err = controller.DeleteBinding(ctx, binding.ID, "operator-1")
	var operation *OperationError
	if !errors.As(err, &operation) || !operation.TokenLive || operation.Code != events.ErrorOpenBaoDenied ||
		!strings.Contains(operation.Message, "could not revoke") {
		t.Fatalf("DeleteBinding(revocation denied) = %#v", err)
	}
	if _, err := controller.Store().Binding(ctx, binding.ID); err == nil {
		t.Fatal("binding still stored after a failed revocation")
	}
	if !tokenValid(t, harness.bao, token) {
		t.Fatal("the token was revoked although OpenBao denied it")
	}
}

func TestAnAgentCannotReportAnotherAgentsTokenAccessor(t *testing.T) {
	ctx := context.Background()
	harness := startHarness(t)
	controller := harness.controller
	keys := map[string]gossh.Signer{"host-a": newAgentKey(t), "host-b": newAgentKey(t)}
	for name, key := range keys {
		_, _ = harness.dial(name, key)
		if err := controller.DecideAgent(ctx, gossh.FingerprintSHA256(key.PublicKey()), true, "operator-1"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := controller.SavePolicy(ctx, policy.New("teal", `path "kv/data/teams/teal/*" { capabilities = ["read"] }`), "operator-1"); err != nil {
		t.Fatal(err)
	}
	theirs, err := controller.CreateBinding(ctx, "host-b", protocol.Key{Kind: protocol.KeyName, Value: "web"}, "teal", "operator-1")
	if err != nil {
		t.Fatal(err)
	}
	ours, err := controller.CreateBinding(ctx, "host-a", protocol.Key{Kind: protocol.KeyName, Value: "web"}, "teal", "operator-1")
	if err != nil {
		t.Fatal(err)
	}
	connection, err := harness.dial("host-a", keys["host-a"])
	if err != nil {
		t.Fatal(err)
	}
	defer connection.client.Close()
	for _, message := range []protocol.Message{
		protocol.Hello{AgentVersion: "test"},
		protocol.TokenAccessor{Binding: theirs.ID, Accessor: "foreignaccessor"},
		protocol.TokenAccessor{Binding: ours.ID, Accessor: "ownaccessor"},
	} {
		if err := connection.conn.Send(message); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		if recorded, err := controller.Store().TokenAccessor(ctx, ours.ID); err == nil && recorded == "ownaccessor" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the agent's own accessor was not recorded")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if recorded, err := controller.Store().TokenAccessor(ctx, theirs.ID); err == nil {
		t.Fatalf("another agent's binding recorded accessor %q", recorded)
	}
}

func TestSessionRejectsMessagesBeforeHelloAndUnknownTypes(t *testing.T) {
	ctx := context.Background()
	harness := startHarness(t)
	key := newAgentKey(t)
	_, _ = harness.dial("host-a", key)
	if err := harness.controller.DecideAgent(ctx, gossh.FingerprintSHA256(key.PublicKey()), true, "operator-1"); err != nil {
		t.Fatal(err)
	}
	connection, err := harness.dial("host-a", key)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.client.Close()
	if err := connection.conn.Send(protocol.Inventory{}); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.conn.Receive(); err == nil {
		t.Fatal("session continued without hello")
	}
	second, err := harness.dial("host-a", key)
	if err != nil {
		t.Fatal(err)
	}
	defer second.client.Close()
	_ = second.conn.Send(protocol.Hello{AgentVersion: "test"})
	_ = second.conn.Send(protocol.Unbind{Binding: "b-1"})
	if _, err := second.conn.Receive(); err == nil {
		t.Fatal("session accepted a controller-to-agent message")
	}
}

func TestMatchBindingsUsesKeyPrecedence(t *testing.T) {
	containers := []protocol.Container{{Keys: []protocol.Key{
		{Kind: protocol.KeyDevcontainer, Value: "/src/app"}, {Kind: protocol.KeyName, Value: "app"},
	}}}
	bindings := []store.Binding{
		{ID: "b-name", Key: protocol.Key{Kind: protocol.KeyName, Value: "app"}},
		{ID: "b-dev", Key: protocol.Key{Kind: protocol.KeyDevcontainer, Value: "/src/app"}},
		{ID: "b-other", Key: protocol.Key{Kind: protocol.KeyName, Value: "other"}},
	}
	matched := MatchBindings(containers, bindings)
	if len(matched) != 1 || matched[0].ID != "b-dev" {
		t.Fatalf("MatchBindings() = %#v", matched)
	}
}

func TestRoleNameIsBoundedToTheManagedPrefix(t *testing.T) {
	if got := RoleName("Host.Example.COM", "b-1"); got != "wyrwood-host-example-com-b-1" {
		t.Fatalf("RoleName() = %q", got)
	}
	if !errors.Is(ErrAgentDisconnected, ErrAgentDisconnected) {
		t.Fatal()
	}
}
