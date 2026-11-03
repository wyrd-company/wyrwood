// ---
// relationships:
//   verifies:
//     - controller
//     - operator-interface
// ---

package controller

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"charm.land/ssh"
	gossh "golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"

	"github.com/wyrd-company/wyrwood/internal/controller/store"
	"github.com/wyrd-company/wyrwood/internal/events"
	"github.com/wyrd-company/wyrwood/internal/openbao"
	"github.com/wyrd-company/wyrwood/internal/policy"
	"github.com/wyrd-company/wyrwood/internal/protocol"
	"github.com/wyrd-company/wyrwood/operator"
)

const samplePolicyHCL = `path "kv/data/sample" { capabilities = ["read"] }`

var fullGrant = operator.Grant{
	Agents: []string{operator.AllNames}, Policies: []string{operator.AllNames},
	Actions: []operator.Action{operator.ActionRead, operator.ActionBind, operator.ActionPolicyWrite},
}

func newEd25519(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return private
}

func (harness *harness) operatorConfig(key gossh.Signer) operator.Config {
	return operator.Config{
		URL: "ssh://" + harness.address, Signer: key, HostKey: gossh.FingerprintSHA256(harness.hostKey),
		Label: "sample-key", Timeout: 5 * time.Second,
	}
}

// approvedOperator returns a connected client whose key holds grant.
func (harness *harness) approvedOperator(t *testing.T, label string, grant operator.Grant) (*operator.Client, gossh.Signer) {
	t.Helper()
	ctx := context.Background()
	key := newAgentKey(t)
	settings := harness.operatorConfig(key)
	settings.Label = label
	if _, err := operator.Login(ctx, settings, nil); err != nil {
		t.Fatal(err)
	}
	if err := harness.controller.ApproveOperatorKey(ctx, gossh.FingerprintSHA256(key.PublicKey()), label, grant, "sample-approver"); err != nil {
		t.Fatal(err)
	}
	client, err := operator.Dial(ctx, settings)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client, key
}

func (harness *harness) approveAgent(t *testing.T, name string) gossh.Signer {
	t.Helper()
	key := newAgentKey(t)
	if _, err := harness.dial(name, key); err == nil {
		t.Fatal("unapproved agent key authenticated")
	}
	if err := harness.controller.DecideAgent(context.Background(), gossh.FingerprintSHA256(key.PublicKey()), true, "sample-approver"); err != nil {
		t.Fatal(err)
	}
	return key
}

func (harness *harness) savePolicy(t *testing.T, name string) {
	t.Helper()
	if _, err := harness.controller.SavePolicy(context.Background(), policy.New(name, samplePolicyHCL), "sample-approver"); err != nil {
		t.Fatal(err)
	}
}

func TestOperatorLoginRecordsAKeyAsPendingUntilApproved(t *testing.T) {
	ctx := context.Background()
	harness := startHarness(t)
	key := newAgentKey(t)
	fingerprint := gossh.FingerprintSHA256(key.PublicKey())
	settings := harness.operatorConfig(key)

	result, err := operator.Login(ctx, settings, nil)
	if err != nil || result.Approved || result.KeyFingerprint != fingerprint || result.HostKey != settings.HostKey {
		t.Fatalf("Login() = %+v, %v", result, err)
	}
	if _, err := operator.Dial(ctx, settings); !errors.Is(err, operator.ErrNotApproved) {
		t.Fatalf("Dial() on a pending key = %v", err)
	}
	stored, err := harness.controller.Store().OperatorKey(ctx, fingerprint)
	if err != nil || stored.State != store.OperatorKeyPending || stored.Label != "sample-key" {
		t.Fatalf("OperatorKey() = %+v, %v", stored, err)
	}
	agents, err := harness.controller.Store().Agents(ctx)
	if err != nil || len(agents) != 0 {
		t.Fatalf("an operator login touched the agent list: %+v, %v", agents, err)
	}

	grant := operator.Grant{Agents: []string{"sample-host"}, Policies: []string{"sample"}, Actions: []operator.Action{operator.ActionRead}}
	if err := harness.controller.ApproveOperatorKey(ctx, fingerprint, "approved-label", grant, "sample-approver"); err != nil {
		t.Fatal(err)
	}
	result, err = operator.Login(ctx, settings, nil)
	if err != nil || !result.Approved {
		t.Fatalf("Login() after approval = %+v, %v", result, err)
	}
	client, err := operator.Dial(ctx, settings)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	identity, err := client.Whoami(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if identity.Label != "approved-label" || identity.Fingerprint != fingerprint || !reflect.DeepEqual(identity.Grant, grant) {
		t.Fatalf("Whoami() = %+v", identity)
	}
}

func TestOperatorHostKeyIsPinned(t *testing.T) {
	ctx := context.Background()
	harness := startHarness(t)
	key := newAgentKey(t)
	settings := harness.operatorConfig(key)

	wrong := settings
	wrong.HostKey = gossh.FingerprintSHA256(newAgentKey(t).PublicKey())
	if _, err := operator.Dial(ctx, wrong); !errors.Is(err, operator.ErrHostKeyMismatch) {
		t.Fatalf("Dial() with another pin = %v", err)
	}
	if _, err := operator.Login(ctx, wrong, nil); !errors.Is(err, operator.ErrHostKeyMismatch) {
		t.Fatalf("Login() with another pin = %v", err)
	}
	unpinned := settings
	unpinned.HostKey = ""
	if _, err := operator.Dial(ctx, unpinned); !errors.Is(err, operator.ErrHostKeyNotAccepted) {
		t.Fatalf("Dial() with no pin = %v", err)
	}
	if _, err := operator.Login(ctx, unpinned, func(string) bool { return false }); !errors.Is(err, operator.ErrHostKeyNotAccepted) {
		t.Fatalf("Login() refused by its caller = %v", err)
	}
	if count, err := harness.controller.Store().PendingOperatorKeyCount(ctx); err != nil || count != 0 {
		t.Fatalf("a refused host key still offered the operator key: %d, %v", count, err)
	}
	var shown string
	result, err := operator.Login(ctx, unpinned, func(fingerprint string) bool { shown = fingerprint; return true })
	if err != nil || result.HostKey != settings.HostKey || shown != settings.HostKey {
		t.Fatalf("Login() accepted = %+v, %q, %v", result, shown, err)
	}
}

func TestOperatorAndAgentKeysCannotCrossRoles(t *testing.T) {
	ctx := context.Background()
	harness := startHarness(t)
	data := harness.controller.Store()

	t.Run("an agent key is not an operator", func(t *testing.T) {
		agentKey := harness.approveAgent(t, "sample-host")
		settings := harness.operatorConfig(agentKey)
		result, err := operator.Login(ctx, settings, nil)
		if err != nil || result.Approved {
			t.Fatalf("Login() with an agent key = %+v, %v", result, err)
		}
		if _, err := data.OperatorKey(ctx, gossh.FingerprintSHA256(agentKey.PublicKey())); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("an agent key was recorded on the operator list: %v", err)
		}
	})

	t.Run("a pending agent key is not recorded as an operator", func(t *testing.T) {
		key := newAgentKey(t)
		if _, err := harness.dial("pending-host", key); err == nil {
			t.Fatal("unapproved agent key authenticated")
		}
		if _, err := operator.Login(ctx, harness.operatorConfig(key), nil); err != nil {
			t.Fatal(err)
		}
		if _, err := data.OperatorKey(ctx, gossh.FingerprintSHA256(key.PublicKey())); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("a pending agent key was recorded on the operator list: %v", err)
		}
	})

	t.Run("an operator key is not an agent", func(t *testing.T) {
		_, key := harness.approvedOperator(t, "sample-operator", fullGrant)
		if _, err := harness.dial("sample-operator", key); err == nil {
			t.Fatal("an operator key authenticated as an agent")
		}
		if _, err := data.Agent(ctx, gossh.FingerprintSHA256(key.PublicKey())); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("an operator key was recorded on the agent list: %v", err)
		}
	})

	t.Run("a pending operator key is not recorded as an agent", func(t *testing.T) {
		key := newAgentKey(t)
		if _, err := operator.Login(ctx, harness.operatorConfig(key), nil); err != nil {
			t.Fatal(err)
		}
		if _, err := harness.dial("other-host", key); err == nil {
			t.Fatal("a pending operator key authenticated as an agent")
		}
		if _, err := data.Agent(ctx, gossh.FingerprintSHA256(key.PublicKey())); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("a pending operator key was recorded on the agent list: %v", err)
		}
	})

	t.Run("an operator connection cannot open the agent subsystem", func(t *testing.T) {
		_, key := harness.approvedOperator(t, "subsystem-operator", fullGrant)
		connection, err := gossh.Dial("tcp", harness.address, &gossh.ClientConfig{
			User: operator.User("subsystem-operator"), Auth: []gossh.AuthMethod{gossh.PublicKeys(key)},
			HostKeyCallback: gossh.FixedHostKey(harness.hostKey), Timeout: 5 * time.Second,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close()
		assertSubsystemCloses(t, connection, protocol.SubsystemName)
	})

	t.Run("an agent connection cannot open the operator subsystem", func(t *testing.T) {
		key := harness.approveAgent(t, "subsystem-host")
		connection, err := gossh.Dial("tcp", harness.address, &gossh.ClientConfig{
			User: "subsystem-host", Auth: []gossh.AuthMethod{gossh.PublicKeys(key)},
			HostKeyCallback: gossh.FixedHostKey(harness.hostKey), Timeout: 5 * time.Second,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close()
		assertSubsystemCloses(t, connection, operator.SubsystemName)
	})
}

// assertSubsystemCloses checks that the subsystem ends with no answer to a request.
func assertSubsystemCloses(t *testing.T, connection *gossh.Client, name string) {
	t.Helper()
	session, err := connection.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	stdin, err := session.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := session.RequestSubsystem(name); err != nil {
		t.Fatal(err)
	}
	_, _ = stdin.Write([]byte(`{"version":1,"operation":"whoami"}` + "\n"))
	output, err := io.ReadAll(stdout)
	if err != nil || len(output) != 0 {
		t.Fatalf("subsystem %s answered %q, %v", name, output, err)
	}
}

// fakeAuthContext holds what authenticate reads and writes on an SSH context.
type fakeAuthContext struct {
	ssh.Context
	user   string
	values map[any]any
}

func (ctx *fakeAuthContext) User() string            { return ctx.user }
func (ctx *fakeAuthContext) SetValue(key, value any) { ctx.values[key] = value }
func (ctx *fakeAuthContext) Value(key any) any       { return ctx.values[key] }

// SSH calls authenticate for each key a client offers. A key that was offered
// and accepted, and then not used, must not stay as the connection's identity.
func TestAnOfferedKeyLeavesNoIdentityWhenALaterKeyFails(t *testing.T) {
	harness := startHarness(t)
	agentKey := harness.approveAgent(t, "sample-host")
	_, operatorKey := harness.approvedOperator(t, "sample-operator", fullGrant)
	unknown := newAgentKey(t).PublicKey()
	for name, first := range map[string]struct {
		user string
		key  gossh.PublicKey
	}{
		"agent":    {"sample-host", agentKey.PublicKey()},
		"operator": {operator.User("sample-operator"), operatorKey.PublicKey()},
	} {
		t.Run(name, func(t *testing.T) {
			ctx := &fakeAuthContext{user: first.user, values: map[any]any{}}
			if !harness.controller.authenticate(ctx, first.key) {
				t.Fatal("the approved key was refused")
			}
			ctx.user = operator.User("other")
			if harness.controller.authenticate(ctx, unknown) {
				t.Fatal("an unknown key was accepted")
			}
			if _, ok := ctx.Value(agentContextKey{}).(authenticatedAgent); ok {
				t.Fatal("the agent identity outlived its key")
			}
			if _, ok := ctx.Value(operatorContextKey{}).(string); ok {
				t.Fatal("the operator identity outlived its key")
			}
		})
	}
}

func TestOperatorConnectionOffersOnlyTheSelectedAgentKey(t *testing.T) {
	ctx := context.Background()
	harness := startHarness(t)
	keyring := sshagent.NewKeyring()
	for _, comment := range []string{"unrelated-git-key", "selected-key", "another-key"} {
		private := newEd25519(t)
		if err := keyring.Add(sshagent.AddedKey{PrivateKey: private, Comment: comment}); err != nil {
			t.Fatal(err)
		}
	}
	signer, err := operator.SelectAgentKey(keyring, "selected-key")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := operator.Login(ctx, harness.operatorConfig(signer), nil); err != nil {
		t.Fatal(err)
	}
	keys, err := harness.controller.Store().OperatorKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0].Fingerprint != gossh.FingerprintSHA256(signer.PublicKey()) {
		t.Fatalf("recorded keys = %+v", keys)
	}
	if err := harness.controller.ApproveOperatorKey(ctx, keys[0].Fingerprint, "agent-held", fullGrant, "sample-approver"); err != nil {
		t.Fatal(err)
	}
	client, err := operator.Dial(ctx, harness.operatorConfig(signer))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if identity, err := client.Whoami(ctx); err != nil || identity.Label != "agent-held" {
		t.Fatalf("Whoami() = %+v, %v", identity, err)
	}
}

func TestApprovalValidatesLabelAndGrant(t *testing.T) {
	ctx := context.Background()
	harness := startHarness(t)
	key := newAgentKey(t)
	fingerprint := gossh.FingerprintSHA256(key.PublicKey())
	if _, err := operator.Login(ctx, harness.operatorConfig(key), nil); err != nil {
		t.Fatal(err)
	}
	read := []operator.Action{operator.ActionRead}
	for name, attempt := range map[string]struct {
		label string
		grant operator.Grant
	}{
		"bad label":      {"not a label", operator.Grant{Actions: read}},
		"no action":      {"valid-label", operator.Grant{Agents: []string{"sample-host"}}},
		"unknown action": {"valid-label", operator.Grant{Actions: []operator.Action{"admin"}}},
		"bad agent":      {"valid-label", operator.Grant{Actions: read, Agents: []string{"not a host"}}},
		"bad policy":     {"valid-label", operator.Grant{Actions: read, Policies: []string{"Not_A_Slug"}}},
		"mixed all":      {"valid-label", operator.Grant{Actions: read, Agents: []string{operator.AllNames, "sample-host"}}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := harness.controller.ApproveOperatorKey(ctx, fingerprint, attempt.label, attempt.grant, "sample-approver"); err == nil {
				t.Fatal("the approval was accepted")
			}
			stored, err := harness.controller.Store().OperatorKey(ctx, fingerprint)
			if err != nil || stored.State != store.OperatorKeyPending {
				t.Fatalf("OperatorKey() = %+v, %v", stored, err)
			}
		})
	}
}

// One label names one key for all time, so that an audit subject stays true.
func TestALabelCannotBeReusedAfterRevocation(t *testing.T) {
	ctx := context.Background()
	harness := startHarness(t)
	_, first := harness.approvedOperator(t, "sample-label", fullGrant)
	second := newAgentKey(t)
	secondFingerprint := gossh.FingerprintSHA256(second.PublicKey())
	if _, err := operator.Login(ctx, harness.operatorConfig(second), nil); err != nil {
		t.Fatal(err)
	}
	if err := harness.controller.ApproveOperatorKey(ctx, secondFingerprint, "sample-label", fullGrant, "sample-approver"); err == nil {
		t.Fatal("a held label was approved for a second key")
	}
	if err := harness.controller.RevokeOperatorKey(ctx, gossh.FingerprintSHA256(first.PublicKey()), "sample-approver"); err != nil {
		t.Fatal(err)
	}
	if err := harness.controller.ApproveOperatorKey(ctx, secondFingerprint, "sample-label", fullGrant, "sample-approver"); err == nil {
		t.Fatal("a revoked key's label was approved for a second key")
	}
}

func TestRevocationEndsAnOpenSessionAndLaterConnections(t *testing.T) {
	ctx := context.Background()
	harness := startHarness(t)
	client, key := harness.approvedOperator(t, "sample-operator", fullGrant)
	fingerprint := gossh.FingerprintSHA256(key.PublicKey())
	if _, err := client.Whoami(ctx); err != nil {
		t.Fatal(err)
	}
	if err := harness.controller.RevokeOperatorKey(ctx, fingerprint, "sample-approver"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Whoami(ctx); !errors.Is(err, operator.ErrNotApproved) {
		t.Fatalf("Whoami() on the open session after revocation = %v", err)
	}
	settings := harness.operatorConfig(key)
	settings.Label = "sample-operator"
	if _, err := operator.Dial(ctx, settings); !errors.Is(err, operator.ErrNotApproved) {
		t.Fatalf("Dial() after revocation = %v", err)
	}
	if result, err := operator.Login(ctx, settings, nil); err != nil || result.Approved {
		t.Fatalf("Login() after revocation = %+v, %v", result, err)
	}
	stored, err := harness.controller.Store().OperatorKey(ctx, fingerprint)
	if err != nil || stored.State != store.OperatorKeyRevoked || stored.RevokedBy != "sample-approver" {
		t.Fatalf("OperatorKey() = %+v, %v", stored, err)
	}
	if err := harness.controller.ApproveOperatorKey(ctx, fingerprint, "sample-operator", fullGrant, "sample-approver"); err == nil {
		t.Fatal("a revoked key was approved again")
	}
	if !hasEvent(t, harness, events.Event{Operation: events.OperationOperatorKeyRevoked, Fingerprint: fingerprint, Operator: "sample-approver"}) {
		t.Fatal("the revocation has no event")
	}
}

func hasEvent(t *testing.T, harness *harness, wanted events.Event) bool {
	t.Helper()
	records := harness.controller.Events().Recent(1000)
	for _, record := range records {
		if record.Operation == wanted.Operation && record.Fingerprint == wanted.Fingerprint && record.Operator == wanted.Operator &&
			(wanted.ErrorCode == "" || record.ErrorCode == wanted.ErrorCode) && (wanted.Agent == "" || record.Agent == wanted.Agent) {
			return true
		}
	}
	return false
}

func TestOperatorGrantBoundsEveryAction(t *testing.T) {
	ctx := context.Background()
	harness := startHarness(t)
	harness.approveAgent(t, "inside-host")
	harness.approveAgent(t, "outside-host")
	harness.savePolicy(t, "allowed")
	harness.savePolicy(t, "forbidden")
	grant := operator.Grant{Agents: []string{"inside-host"}, Policies: []string{"allowed"}, Actions: []operator.Action{operator.ActionRead, operator.ActionBind, operator.ActionPolicyWrite}}
	client, _ := harness.approvedOperator(t, "scoped-key", grant)
	subject := "key:scoped-key"
	name := func(value string) operator.Key { return operator.Key{Kind: operator.KeyName, Value: value} }
	wide, _ := harness.approvedOperator(t, "wide-key", fullGrant)

	// Bindings the wide key sets up, each outside the scoped grant in one way.
	onOutsideAgent, err := wide.Bind(ctx, operator.BindRequest{Agent: "outside-host", Key: name("app-a"), Policies: []string{"allowed"}})
	if err != nil {
		t.Fatal(err)
	}
	heldForbidden, err := wide.Bind(ctx, operator.BindRequest{Agent: "inside-host", Key: name("app-b"), Policies: []string{"allowed", "forbidden"}})
	if err != nil {
		t.Fatal(err)
	}

	assertOutside := func(t *testing.T, err error) {
		t.Helper()
		if !errors.Is(err, operator.ErrOutsideGrant) {
			t.Fatalf("error = %v; want outside the grant", err)
		}
	}
	t.Run("bind on another agent", func(t *testing.T) {
		_, err := client.Bind(ctx, operator.BindRequest{Agent: "outside-host", Key: name("app-c"), Policies: []string{"allowed"}})
		assertOutside(t, err)
		if !hasEvent(t, harness, events.Event{Operation: events.OperationBindingCreated, Operator: subject, ErrorCode: events.ErrorOutsideGrant, Agent: "outside-host"}) {
			t.Fatal("the refused bind has no audit event")
		}
	})
	t.Run("bind with another policy", func(t *testing.T) {
		_, err := client.Bind(ctx, operator.BindRequest{Agent: "inside-host", Key: name("app-c"), Policies: []string{"allowed", "forbidden"}})
		assertOutside(t, err)
	})
	t.Run("a binding holding another policy cannot be touched", func(t *testing.T) {
		_, err := client.Bind(ctx, operator.BindRequest{Agent: "inside-host", Key: name("app-b"), Policies: []string{"allowed"}})
		assertOutside(t, err)
		_, err = client.GetBinding(ctx, heldForbidden.ID)
		assertOutside(t, err)
		_, err = client.Unbind(ctx, operator.UnbindRequest{ID: heldForbidden.ID})
		assertOutside(t, err)
		key := name("app-b")
		_, err = client.Unbind(ctx, operator.UnbindRequest{Agent: "inside-host", Key: &key})
		assertOutside(t, err)
		if _, err := harness.controller.Store().Binding(ctx, heldForbidden.ID); err != nil {
			t.Fatalf("the binding is gone: %v", err)
		}
	})
	t.Run("a binding on another agent cannot be touched", func(t *testing.T) {
		_, err := client.GetBinding(ctx, onOutsideAgent.ID)
		assertOutside(t, err)
		_, err = client.Unbind(ctx, operator.UnbindRequest{ID: onOutsideAgent.ID})
		assertOutside(t, err)
		key := name("app-a")
		_, err = client.Unbind(ctx, operator.UnbindRequest{Agent: "outside-host", Key: &key})
		assertOutside(t, err)
		_, err = client.ListBindings(ctx, operator.BindingList{Agent: "outside-host"})
		assertOutside(t, err)
		// A key cannot learn from an unbind what another agent has no binding for.
		missing := name("never-bound")
		_, err = client.Unbind(ctx, operator.UnbindRequest{Agent: "outside-host", Key: &missing})
		assertOutside(t, err)
	})
	t.Run("policy reads", func(t *testing.T) {
		_, err := client.GetPolicy(ctx, "forbidden")
		assertOutside(t, err)
		policies, err := client.ListPolicies(ctx)
		if err != nil || len(policies) != 1 || policies[0].Name != "allowed" {
			t.Fatalf("ListPolicies() = %+v, %v", policies, err)
		}
	})
	t.Run("policy write outside the list", func(t *testing.T) {
		_, err := client.PutPolicy(ctx, operator.PolicyPut{Name: "forbidden", HCL: samplePolicyHCL})
		assertOutside(t, err)
		_, err = client.PutPolicy(ctx, operator.PolicyPut{Name: "brand-new", HCL: samplePolicyHCL})
		assertOutside(t, err)
		if !hasEvent(t, harness, events.Event{Operation: events.OperationPolicySaved, Operator: subject, ErrorCode: events.ErrorOutsideGrant}) {
			t.Fatal("the refused write has no audit event")
		}
	})
	t.Run("policy write reaching a binding outside the grant", func(t *testing.T) {
		before, err := harness.controller.Store().Policy(ctx, "allowed")
		if err != nil {
			t.Fatal(err)
		}
		_, err = client.PutPolicy(ctx, operator.PolicyPut{Name: "allowed", HCL: `path "kv/data/changed" { capabilities = ["read"] }`})
		assertOutside(t, err)
		after, err := harness.controller.Store().Policy(ctx, "allowed")
		if err != nil || after.Policy.Revision != before.Policy.Revision {
			t.Fatalf("the policy changed: %+v, %v", after, err)
		}
	})
	t.Run("the list leaves out what the grant does not cover", func(t *testing.T) {
		mine, err := client.Bind(ctx, operator.BindRequest{Agent: "inside-host", Key: name("app-d"), Policies: []string{"allowed"}})
		if err != nil {
			t.Fatal(err)
		}
		listed, err := client.ListBindings(ctx, operator.BindingList{})
		if err != nil || len(listed) != 1 || listed[0].ID != mine.ID {
			t.Fatalf("ListBindings() = %+v, %v", listed, err)
		}
		if got, err := client.GetBinding(ctx, mine.ID); err != nil || got.ID != mine.ID {
			t.Fatalf("GetBinding() = %+v, %v", got, err)
		}
		stored, err := harness.controller.Store().Binding(ctx, mine.ID)
		if err != nil || stored.CreatedBy != subject {
			t.Fatalf("Binding() = %+v, %v; want created by %s", stored, err, subject)
		}
		if !hasEvent(t, harness, events.Event{Operation: events.OperationBindingCreated, Operator: subject, Agent: "inside-host"}) {
			t.Fatal("the bind has no audit event naming the key")
		}
	})
}

func TestOperatorActionsAreChecked(t *testing.T) {
	ctx := context.Background()
	harness := startHarness(t)
	harness.approveAgent(t, "sample-host")
	harness.savePolicy(t, "sample")
	wide, _ := harness.approvedOperator(t, "wide-key", fullGrant)
	key := operator.Key{Kind: operator.KeyName, Value: "app"}
	existing, err := wide.Bind(ctx, operator.BindRequest{Agent: "sample-host", Key: key, Policies: []string{"sample"}})
	if err != nil {
		t.Fatal(err)
	}
	everything := func(actions ...operator.Action) operator.Grant {
		return operator.Grant{Agents: []string{operator.AllNames}, Policies: []string{operator.AllNames}, Actions: actions}
	}
	readOnly, _ := harness.approvedOperator(t, "read-key", everything(operator.ActionRead))
	bindOnly, _ := harness.approvedOperator(t, "bind-key", everything(operator.ActionBind))
	writeOnly, _ := harness.approvedOperator(t, "write-key", everything(operator.ActionPolicyWrite))
	put := operator.PolicyPut{Name: "sample", HCL: samplePolicyHCL}
	bind := operator.BindRequest{Agent: "sample-host", Key: operator.Key{Kind: operator.KeyName, Value: "other"}, Policies: []string{"sample"}}

	for name, attempt := range map[string]func() error{
		"read cannot write":    func() error { _, err := readOnly.PutPolicy(ctx, put); return err },
		"read cannot bind":     func() error { _, err := readOnly.Bind(ctx, bind); return err },
		"read cannot unbind":   func() error { _, err := readOnly.Unbind(ctx, operator.UnbindRequest{ID: existing.ID}); return err },
		"bind cannot write":    func() error { _, err := bindOnly.PutPolicy(ctx, put); return err },
		"bind cannot list":     func() error { _, err := bindOnly.ListBindings(ctx, operator.BindingList{}); return err },
		"bind cannot read":     func() error { _, err := bindOnly.GetBinding(ctx, existing.ID); return err },
		"bind cannot policies": func() error { _, err := bindOnly.ListPolicies(ctx); return err },
		"bind cannot get":      func() error { _, err := bindOnly.GetPolicy(ctx, "sample"); return err },
		"write cannot bind":    func() error { _, err := writeOnly.Bind(ctx, bind); return err },
		"write cannot unbind":  func() error { _, err := writeOnly.Unbind(ctx, operator.UnbindRequest{ID: existing.ID}); return err },
		"write cannot read":    func() error { _, err := writeOnly.GetPolicy(ctx, "sample"); return err },
	} {
		t.Run(name, func(t *testing.T) {
			if err := attempt(); !errors.Is(err, operator.ErrOutsideGrant) {
				t.Fatalf("error = %v; want outside the grant", err)
			}
		})
	}
	// The grant check comes before the lookup, so that a key cannot learn what exists.
	if _, err := bindOnly.Unbind(ctx, operator.UnbindRequest{ID: existing.ID}); err != nil {
		t.Fatalf("Unbind() with the bind action = %v", err)
	}
}

func TestOperatorCommandsAreSafeToRepeat(t *testing.T) {
	ctx := context.Background()
	harness := startHarness(t)
	harness.approveAgent(t, "sample-host")
	client, _ := harness.approvedOperator(t, "sample-operator", fullGrant)
	put := operator.PolicyPut{Name: "sample", HCL: samplePolicyHCL}
	first, err := client.PutPolicy(ctx, put)
	if err != nil || first.Revision != 1 || first.HCL != samplePolicyHCL {
		t.Fatalf("PutPolicy() = %+v, %v", first, err)
	}
	second, err := client.PutPolicy(ctx, put)
	if err != nil || second.Revision != first.Revision {
		t.Fatalf("PutPolicy() again = %+v, %v", second, err)
	}

	group := uint32(1000)
	key := operator.Key{Kind: operator.KeyName, Value: "app"}
	request := operator.BindRequest{Agent: "sample-host", Key: key, Policies: []string{"sample"}, Settings: operator.Settings{AccessGroup: &group}}
	bound, err := client.Bind(ctx, request)
	if err != nil || bound.ID == "" || !bound.Applied || bound.Revision != 1 {
		t.Fatalf("Bind() = %+v, %v", bound, err)
	}
	if bound.Settings.AccessGroup == nil || *bound.Settings.AccessGroup != group {
		t.Fatalf("Bind() settings = %+v", bound.Settings)
	}
	again, err := client.Bind(ctx, request)
	if err != nil || again.ID != bound.ID || again.Revision != bound.Revision {
		t.Fatalf("Bind() again = %+v, %v", again, err)
	}

	other := request
	other.Settings = operator.Settings{}
	if _, err := client.Bind(ctx, other); !errors.Is(err, operator.ErrBindingDiffers) {
		t.Fatalf("Bind() with another selection = %v", err)
	}
	stored, err := harness.controller.Store().Binding(ctx, bound.ID)
	if err != nil || stored.Revision != 1 || stored.Settings.AccessGroup == nil {
		t.Fatalf("the refused bind changed the binding: %+v, %v", stored, err)
	}

	result, err := client.Unbind(ctx, operator.UnbindRequest{Agent: "sample-host", Key: &key})
	if err != nil || !result.Removed {
		t.Fatalf("Unbind() = %+v, %v", result, err)
	}
	for _, repeat := range []operator.UnbindRequest{{Agent: "sample-host", Key: &key}, {ID: bound.ID}, {ID: "b-unknown"}} {
		result, err := client.Unbind(ctx, repeat)
		if err != nil || result.Removed || result.TokenLive {
			t.Fatalf("Unbind(%+v) again = %+v, %v", repeat, result, err)
		}
	}
	if _, err := client.GetBinding(ctx, bound.ID); !errors.Is(err, operator.ErrNotFound) {
		t.Fatalf("GetBinding() after unbind = %v", err)
	}
}

func TestUnbindSelectsByIDOrByAgentAndKey(t *testing.T) {
	ctx := context.Background()
	harness := startHarness(t)
	client, _ := harness.approvedOperator(t, "sample-operator", fullGrant)
	key := operator.Key{Kind: operator.KeyName, Value: "app"}
	for _, request := range []operator.UnbindRequest{{}, {Agent: "sample-host"}, {Key: &key}, {ID: "b-x", Agent: "sample-host", Key: &key}} {
		if _, err := client.Unbind(ctx, request); !errors.Is(err, operator.ErrInvalid) {
			t.Fatalf("Unbind(%+v) = %v", request, err)
		}
	}
}

// failingRoleOpenBao fails WriteRole while failing is true.
type failingRoleOpenBao struct {
	OpenBao
	failing *bool
}

func (wrapped failingRoleOpenBao) WriteRole(ctx context.Context, role string, policyNames []string, tokenTTL, tokenMaxTTL time.Duration) error {
	if *wrapped.failing {
		return &openbao.Error{Category: openbao.CategoryUnavailable}
	}
	return wrapped.OpenBao.WriteRole(ctx, role, policyNames, tokenTTL, tokenMaxTTL)
}

func TestARepeatedBindFinishesAPendingAssignment(t *testing.T) {
	ctx := context.Background()
	failing := false
	harness := startHarnessWith(t, func(inner OpenBao) OpenBao { return failingRoleOpenBao{inner, &failing} })
	harness.approveAgent(t, "sample-host")
	harness.savePolicy(t, "sample")
	client, _ := harness.approvedOperator(t, "sample-operator", fullGrant)
	request := operator.BindRequest{Agent: "sample-host", Key: operator.Key{Kind: operator.KeyName, Value: "app"}, Policies: []string{"sample"}}
	failing = true
	if _, err := client.Bind(ctx, request); !errors.Is(err, operator.ErrPending) {
		t.Fatalf("Bind() while OpenBao fails = %v", err)
	}
	if _, err := client.Bind(ctx, request); !errors.Is(err, operator.ErrPending) {
		t.Fatalf("Bind() again while OpenBao fails = %v", err)
	}
	failing = false
	bound, err := client.Bind(ctx, request)
	if err != nil || !bound.Applied {
		t.Fatalf("Bind() after recovery = %+v, %v", bound, err)
	}
	stored, err := harness.controller.Store().Binding(ctx, bound.ID)
	if err != nil || !stored.Applied {
		t.Fatalf("Binding() = %+v, %v", stored, err)
	}
}

func TestPolicyPutKeepsWhatItDoesNotSet(t *testing.T) {
	ctx := context.Background()
	harness := startHarness(t)
	client, _ := harness.approvedOperator(t, "sample-operator", fullGrant)
	if err := harness.controller.openbao.CreateTransitKey(ctx, "first-key", "ed25519"); err != nil {
		t.Fatal(err)
	}
	if err := harness.controller.openbao.CreateTransitKey(ctx, "second-key", "ed25519"); err != nil {
		t.Fatal(err)
	}
	document := policy.New("sample", samplePolicyHCL)
	document.Contract.MountTarget = "/run/custom"
	document.SSH = &policy.SSH{TransitKeys: []string{"first-key", "second-key"}, NotForwardable: &policy.SSHIdentityNames{TransitKeys: []string{"first-key", "second-key"}}}
	if _, err := harness.controller.SavePolicy(ctx, document, "sample-approver"); err != nil {
		t.Fatal(err)
	}

	changedHCL := `path "kv/data/changed" { capabilities = ["read"] }`
	saved, err := client.PutPolicy(ctx, operator.PolicyPut{Name: "sample", HCL: changedHCL})
	if err != nil || saved.HCL != changedHCL || saved.SSH == nil || len(saved.SSH.TransitKeys) != 2 {
		t.Fatalf("PutPolicy() = %+v, %v", saved, err)
	}
	stored, err := harness.controller.Store().Policy(ctx, "sample")
	if err != nil || stored.Policy.Contract.MountTarget != "/run/custom" || stored.SavedBy != "key:sample-operator" {
		t.Fatalf("Policy() = %+v, %v", stored, err)
	}

	if _, err := client.PutPolicy(ctx, operator.PolicyPut{Name: "sample", HCL: changedHCL, SSH: &operator.PolicySSH{TransitKeys: []string{"second-key"}}}); err != nil {
		t.Fatal(err)
	}
	stored, err = harness.controller.Store().Policy(ctx, "sample")
	if err != nil || !reflect.DeepEqual(stored.Policy.SSH.TransitKeys, []string{"second-key"}) ||
		!reflect.DeepEqual(stored.Policy.SSH.NotForwardable.TransitKeys, []string{"second-key"}) {
		t.Fatalf("SSH after replacing it = %+v, %v", stored.Policy.SSH, err)
	}
	if _, err := client.PutPolicy(ctx, operator.PolicyPut{Name: "sample", HCL: changedHCL, SSH: &operator.PolicySSH{}}); err != nil {
		t.Fatal(err)
	}
	stored, err = harness.controller.Store().Policy(ctx, "sample")
	if err != nil || stored.Policy.SSH != nil {
		t.Fatalf("SSH after clearing it = %+v, %v", stored.Policy.SSH, err)
	}
	if _, err := client.PutPolicy(ctx, operator.PolicyPut{Name: "Not_A_Slug", HCL: samplePolicyHCL}); !errors.Is(err, operator.ErrInvalid) {
		t.Fatalf("PutPolicy() with a bad name = %v", err)
	}
}

// A name binding before its container exists reads as waiting on the container,
// with the agent connected, so that a script can tell it is not ready yet.
func TestOperatorBindingReportsReadiness(t *testing.T) {
	ctx := context.Background()
	harness := startHarness(t)
	harness.approveAgent(t, "sample-host")
	harness.savePolicy(t, "sample")
	client, _ := harness.approvedOperator(t, "sample-operator", fullGrant)
	bound, err := client.Bind(ctx, operator.BindRequest{Agent: "sample-host", Key: operator.Key{Kind: operator.KeyName, Value: "app"}, Policies: []string{"sample"}})
	if err != nil {
		t.Fatal(err)
	}
	if bound.Status.Binding != bound.ID || bound.Status.Readiness != operator.ReadinessUnknown || bound.Status.AgentConnected {
		t.Fatalf("status with no agent session = %+v", bound.Status)
	}
	listed, err := client.ListBindings(ctx, operator.BindingList{Agent: "sample-host"})
	if err != nil || len(listed) != 1 || listed[0].Status.Binding != bound.ID || listed[0].Status.Readiness != operator.ReadinessUnknown {
		t.Fatalf("ListBindings() = %+v, %v", listed, err)
	}
	encoded, err := json.Marshal(listed)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{"secret", "role-id", "accessor", "\"role\""} {
		if strings.Contains(strings.ToLower(string(encoded)), private) {
			t.Fatalf("the binding output holds %q: %s", private, encoded)
		}
	}
}

// The public status type is a copy of the controller's, and this keeps them equal.
func TestPublicBindingStatusCarriesEveryField(t *testing.T) {
	group := uint32(1000)
	status := BindingStatus{
		Binding: "b-1", Agent: "sample-host", Key: protocol.Key{Kind: protocol.KeyName, Value: "app"}, AgentConnected: true,
		LastReport: time.Unix(1700000000, 0).UTC(), Readiness: ReadinessFailed, Reasons: []NotReadyReason{ReasonConsumerDirectory},
		Containers: []BindingContainer{{ID: strings.Repeat("a", 64), Name: "app", State: protocol.StateRunning}},
		Consumers:  []protocol.ConsumerStatus{{Directory: "/run/wyrwood/containers/app", ContainerID: strings.Repeat("a", 64), AccessGroup: &group, Sockets: []protocol.Socket{protocol.SocketVault}, Failed: protocol.FailedItem("consumer-directory")}},
		Token:      protocol.TokenState("valid"), Outcome: protocol.OutcomeNonConforming, FailedItems: []protocol.FailedItem{"consumer-directory"},
		Reason: protocol.Reason("sample-reason"), LastError: protocol.CredentialError("openbao-denied"),
	}
	want, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(want))
	decoder.DisallowUnknownFields()
	var public operator.BindingStatus
	if err := decoder.Decode(&public); err != nil {
		t.Fatalf("the public type lacks a field: %v", err)
	}
	got, err := json.Marshal(public)
	if err != nil {
		t.Fatal(err)
	}
	var wantFields, gotFields map[string]any
	if err := json.Unmarshal(want, &wantFields); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(got, &gotFields); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(wantFields, gotFields) {
		t.Fatalf("public status = %s; want %s", got, want)
	}
	if converted, err := publicStatus(status); err != nil || !reflect.DeepEqual(converted, public) {
		t.Fatalf("publicStatus() = %+v, %v", converted, err)
	}
}

func TestOperatorRequestsAreValidated(t *testing.T) {
	harness := startHarness(t)
	_, key := harness.approvedOperator(t, "sample-operator", fullGrant)
	fingerprint := gossh.FingerprintSHA256(key.PublicKey())
	ctx := context.Background()
	for name, line := range map[string]string{
		"not JSON":           `not json`,
		"wrong version":      `{"version":2,"operation":"whoami"}`,
		"unknown operation":  `{"version":1,"operation":"delete-everything"}`,
		"unknown field":      `{"version":1,"operation":"whoami","extra":true}`,
		"unknown body field": `{"version":1,"operation":"policy-get","body":{"name":"sample","extra":true}}`,
		"missing body":       `{"version":1,"operation":"policy-get"}`,
	} {
		t.Run(name, func(t *testing.T) {
			response := harness.controller.answerOperator(ctx, fingerprint, []byte(line))
			if response.Error == nil || response.Error.Code != operator.CodeInvalid {
				t.Fatalf("response = %+v", response)
			}
		})
	}
	if response := harness.controller.answerOperator(ctx, "SHA256:unknown", []byte(`{"version":1,"operation":"whoami"}`)); response.Error == nil || response.Error.Code != operator.CodeNotApproved {
		t.Fatalf("response for an unknown key = %+v", response)
	}
}

func TestOversizedResponseIsAnError(t *testing.T) {
	encoded, err := encodeOperatorResponse(operator.Response{Version: operator.ProtocolVersion, Body: json.RawMessage(`"` + strings.Repeat("a", operator.MaximumResponseBytes) + `"`)})
	if err != nil {
		t.Fatal(err)
	}
	var response operator.Response
	if err := json.Unmarshal(encoded, &response); err != nil {
		t.Fatal(err)
	}
	if response.Error == nil || response.Error.Code != operator.CodeFailed || len(encoded) >= operator.MaximumResponseBytes {
		t.Fatalf("response = %.200s", encoded)
	}
}
