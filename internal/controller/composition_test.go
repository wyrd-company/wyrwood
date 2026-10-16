// ---
// relationships:
//   verifies: composable-policy-bindings
// ---

package controller

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"github.com/wyrd-company/wyrwood/internal/controller/store"
	"github.com/wyrd-company/wyrwood/internal/policy"
	"github.com/wyrd-company/wyrwood/internal/protocol"
	gossh "golang.org/x/crypto/ssh"
	"io"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"
)

func TestMultiplePoliciesIssueExactOwnTokenAndRevokeOnOfflineChange(t *testing.T) {
	ctx := context.Background()
	h := startHarness(t)
	c := h.controller
	key := newAgentKey(t)
	_, _ = h.dial("host-a", key)
	if err := c.DecideAgent(ctx, gossh.FingerprintSHA256(key.PublicKey()), true, "operator-1"); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"alpha", "beta"} {
		if _, err := c.SavePolicy(ctx, policy.New(name, policy.StarterHCL), "operator-1"); err != nil {
			t.Fatal(err)
		}
	}
	zero := uint32(0)
	b, err := c.CreateBinding(ctx, "host-a", protocol.Key{Kind: protocol.KeyName, Value: "example"}, BindingRequest{Policies: []string{"beta", "alpha"}, Settings: policy.Settings{TokenTTL: "20m", TokenMaxTTL: "2h", AccessGroup: &zero}}, "operator-1")
	if err != nil {
		t.Fatal(err)
	}
	first, err := appRoleLogin(t, h.bao, b.Role)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first.Policies, []string{"wyrwood-alpha", "wyrwood-beta"}) {
		t.Fatalf("issued policies = %v", first.Policies)
	}
	late, err := appRoleLogin(t, h.bao, b.Role)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.store.SaveAssignmentAccessor(ctx, b, first.Accessor, c.now()); err != nil {
		t.Fatal(err)
	}
	if err := c.ChangeBinding(ctx, b.ID, BindingRequest{Policies: []string{"alpha"}, Settings: b.Settings, Revision: b.Revision}, "operator-1"); err != nil {
		t.Fatal(err)
	}
	if tokenValid(t, h.bao, first) {
		t.Fatal("reported old token remains valid while agent is offline")
	}
	current, err := c.store.Binding(ctx, b.ID)
	if err != nil {
		t.Fatal(err)
	}
	if current.Assignment() == b.Assignment() || !current.Applied || len(current.Policies) != 1 || current.Settings.AccessGroup == nil || *current.Settings.AccessGroup != 0 {
		t.Fatal("durable assignment or settings lost")
	}
	token, err := appRoleLogin(t, h.bao, current.Role)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(token.Policies, []string{"wyrwood-alpha"}) {
		t.Fatal(token.Policies)
	}
	session := agentSession{controller: c, agent: "host-a", conn: protocol.NewConn(&bytes.Buffer{})}
	if err := session.recordAccessor(ctx, protocol.TokenAccessor{Binding: b.ID, Assignment: current.Assignment(), Accessor: token.Accessor}); err != nil {
		t.Fatal(err)
	}
	if err := session.recordAccessor(ctx, protocol.TokenAccessor{Binding: b.ID, Assignment: b.Assignment(), Accessor: late.Accessor}); err != nil {
		t.Fatal(err)
	}
	if tokenValid(t, h.bao, late) {
		t.Fatal("late old-assignment token remains valid")
	}
	if got, _ := c.store.TokenAccessor(ctx, b.ID); got != token.Accessor {
		t.Fatal("stale report replaced the current accessor")
	}
}

func TestPolicyEditRejectsAffectedBindingConflictBeforePublishing(t *testing.T) {
	ctx := context.Background()
	h := startHarness(t)
	c := h.controller
	key := newAgentKey(t)
	_, _ = h.dial("host-a", key)
	if err := c.DecideAgent(ctx, gossh.FingerprintSHA256(key.PublicKey()), true, "operator-1"); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"alpha", "beta"} {
		if _, err := c.SavePolicy(ctx, policy.New(name, policy.StarterHCL), "operator-1"); err != nil {
			t.Fatal(err)
		}
	}
	b, err := c.CreateBinding(ctx, "host-a", protocol.Key{Kind: protocol.KeyName, Value: "example"}, BindingRequest{Policies: []string{"alpha", "beta"}}, "operator-1")
	if err != nil {
		t.Fatal(err)
	}
	document := policy.New("beta", policy.StarterHCL)
	document.Contract.MountTarget = "/opt/example"
	if _, err := c.SavePolicy(ctx, document, "operator-1"); err == nil {
		t.Fatal("conflicting edit accepted")
	}
	stored, _ := c.store.Policy(ctx, "beta")
	if stored.Policy.Revision != 1 || stored.Policy.Contract.MountTarget != "/run/wyrwood" {
		t.Fatal("rejected edit persisted")
	}
	current, _ := c.store.Binding(ctx, b.ID)
	if current.Assignment() != b.Assignment() {
		t.Fatal("rejected edit changed binding")
	}
}

func TestUnchangedPolicyDoesNotRevokeOrBumpRevision(t *testing.T) {
	ctx := context.Background()
	h := startHarness(t)
	c := h.controller
	document := policy.New("alpha", policy.StarterHCL)
	saved, err := c.SavePolicy(ctx, document, "operator-1")
	if err != nil {
		t.Fatal(err)
	}
	again, err := c.SavePolicy(ctx, document, "operator-1")
	if err != nil {
		t.Fatal(err)
	}
	if saved.Revision != again.Revision {
		t.Fatal("unchanged save advanced revision")
	}
}

func TestPendingRevocationBlocksIssuanceAndRecoversWithoutAgent(t *testing.T) {
	ctx := context.Background()
	h := startHarness(t)
	c := h.controller
	key := newAgentKey(t)
	_, _ = h.dial("host-a", key)
	if err := c.DecideAgent(ctx, gossh.FingerprintSHA256(key.PublicKey()), true, "operator-1"); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"alpha", "beta"} {
		if _, err := c.SavePolicy(ctx, policy.New(name, policy.StarterHCL), "operator-1"); err != nil {
			t.Fatal(err)
		}
	}
	b, err := c.CreateBinding(ctx, "host-a", protocol.Key{Kind: protocol.KeyName, Value: "example"}, BindingRequest{Policies: []string{"alpha", "beta"}}, "operator-1")
	if err != nil {
		t.Fatal(err)
	}
	token, err := appRoleLogin(t, h.bao, b.Role)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.store.SaveAssignmentAccessor(ctx, b, token.Accessor, c.now()); err != nil {
		t.Fatal(err)
	}
	original := c.openbao
	c.openbao = &failedRevoke{OpenBao: original}
	if err := c.ChangeBinding(ctx, b.ID, BindingRequest{Policies: []string{"alpha"}, Settings: b.Settings, Revision: b.Revision}, "operator-1"); err == nil {
		t.Fatal("failed revocation reported success")
	}
	pending, err := c.store.Binding(ctx, b.ID)
	if err != nil {
		t.Fatal(err)
	}
	if pending.Applied {
		t.Fatal("failed transition marked applied")
	}
	var wire bytes.Buffer
	session := agentSession{controller: c, agent: "host-a", conn: protocol.NewConn(&wire), credentialed: map[string]string{}}
	if err := session.issue(ctx, pending); err != nil {
		t.Fatal(err)
	}
	if wire.Len() != 0 {
		t.Fatal("credential issued before old-token revocation")
	}
	c.openbao = original
	if err := c.reconcileBindings(ctx); err != nil {
		t.Fatal(err)
	}
	current, _ := c.store.Binding(ctx, b.ID)
	if !current.Applied || current.Assignment() != pending.Assignment() {
		t.Fatal("recovery changed or lost desired assignment")
	}
	if tokenValid(t, h.bao, token) {
		t.Fatal("offline old token remains valid after recovery")
	}
}

type failedRevoke struct{ OpenBao }

func (wrapped *failedRevoke) RevokeAccessor(context.Context, string) error {
	return errors.New("test failure")
}

func TestPolicyPublicationRollsBackWhenDatabaseCommitFails(t *testing.T) {
	ctx := context.Background()
	h := startHarness(t)
	c := h.controller
	document := policy.New("alpha", policy.StarterHCL)
	if _, err := c.SavePolicy(ctx, document, "operator-1"); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", filepath.Join(c.config.StateDirectory, "controller.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TRIGGER refuse_policy BEFORE UPDATE ON policies BEGIN SELECT RAISE(ABORT, 'test refusal'); END`); err != nil {
		t.Fatal(err)
	}
	edited := document.Clone()
	edited.OpenBao.Policy += `path "kv/data/example" { capabilities = ["read"] }`
	if _, err := c.SavePolicy(ctx, edited, "operator-1"); err == nil {
		t.Fatal("failed commit reported success")
	}
	actual, err := h.bao.Root.Sys().GetPolicy("wyrwood-alpha")
	if err != nil {
		t.Fatal(err)
	}
	if actual != document.OpenBao.Policy {
		t.Fatal("uncommitted HCL remained active")
	}
	stored, _ := c.store.Policy(ctx, "alpha")
	if stored.Policy.Revision != 1 {
		t.Fatal("failed publication changed revision")
	}
	// Startup repairs a crash between remote publication and the database commit.
	if err := c.openbao.WritePolicy(ctx, "wyrwood-alpha", edited.OpenBao.Policy); err != nil {
		t.Fatal(err)
	}
	if err := c.reconcileBindings(ctx); err != nil {
		t.Fatal(err)
	}
	actual, err = h.bao.Root.Sys().GetPolicy("wyrwood-alpha")
	if err != nil || actual != document.OpenBao.Policy {
		t.Fatal("restart did not restore stored HCL")
	}
}

func TestOpenBaoCombinesOverlappingPoliciesWithDenyAndPathPriority(t *testing.T) {
	ctx := context.Background()
	h := startHarness(t)
	c := h.controller
	key := newAgentKey(t)
	_, _ = h.dial("host-a", key)
	if err := c.DecideAgent(ctx, gossh.FingerprintSHA256(key.PublicKey()), true, "operator-1"); err != nil {
		t.Fatal(err)
	}
	sources := map[string]string{
		"alpha": policy.StarterHCL + `path "kv/data/shared" { capabilities = ["read"] }
 path "kv/data/*" { capabilities = ["read"] }
 path "kv/data/blocked" { capabilities = ["read"] }`,
		"beta": policy.StarterHCL + `path "kv/data/shared" { capabilities = ["update"] }
 path "kv/data/specific" { capabilities = ["update"] }
 path "kv/data/blocked" { capabilities = ["deny"] }`,
	}
	for name, hcl := range sources {
		if _, err := c.SavePolicy(ctx, policy.New(name, hcl), "operator-1"); err != nil {
			t.Fatal(err)
		}
	}
	b, err := c.CreateBinding(ctx, "host-a", protocol.Key{Kind: protocol.KeyName, Value: "example"}, BindingRequest{Policies: []string{"beta", "alpha"}}, "operator-1")
	if err != nil {
		t.Fatal(err)
	}
	token, err := appRoleLogin(t, h.bao, b.Role)
	if err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string][]string{"kv/data/shared": {"read", "update"}, "kv/data/specific": {"update"}, "kv/data/blocked": {"deny"}, "kv/data/other": {"read"}} {
		got, err := h.bao.Root.Sys().Capabilities(token.Value(), path)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s capabilities = %v, want %v", path, got, want)
		}
	}
}

func TestUncertainRemotePolicyWriteRestoresStoredHCL(t *testing.T) {
	ctx := context.Background()
	h := startHarness(t)
	c := h.controller
	original := policy.New("alpha", policy.StarterHCL)
	if _, err := c.SavePolicy(ctx, original, "operator-1"); err != nil {
		t.Fatal(err)
	}
	candidate := original.Clone()
	candidate.OpenBao.Policy += `path "kv/data/example" { capabilities = ["read"] }`
	c.openbao = &lostPolicyResponse{OpenBao: c.openbao, failHCL: candidate.OpenBao.Policy}
	if _, err := c.SavePolicy(ctx, candidate, "operator-1"); err == nil {
		t.Fatal("uncertain publication reported success")
	}
	actual, err := h.bao.Root.Sys().GetPolicy("wyrwood-alpha")
	if err != nil || actual != original.OpenBao.Policy {
		t.Fatal("remote write survived an uncertain response")
	}
}

type lostPolicyResponse struct {
	OpenBao
	failHCL string
}

func (wrapped *lostPolicyResponse) WritePolicy(ctx context.Context, name, hcl string) error {
	if err := wrapped.OpenBao.WritePolicy(ctx, name, hcl); err != nil {
		return err
	}
	if hcl == wrapped.failHCL {
		return errors.New("test lost response")
	}
	return nil
}

func TestStalledCredentialDeliveryDoesNotBlockUnrelatedPolicySave(t *testing.T) {
	h, b := newSingleBinding(t)
	stalled := &stalledStream{started: make(chan struct{}), release: make(chan struct{})}
	session := agentSession{controller: h.controller, agent: b.Agent, conn: protocol.NewConn(stalled), credentialed: map[string]string{}}
	done := make(chan error, 1)
	go func() { done <- session.issue(context.Background(), b) }()
	defer func() { close(stalled.release); <-done }()
	<-stalled.started
	saved := make(chan error, 1)
	go func() {
		_, err := h.controller.SavePolicy(context.Background(), policy.New("unrelated", policy.StarterHCL), "operator-1")
		saved <- err
	}()
	select {
	case err := <-saved:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("stalled agent blocked unrelated policy save")
	}
}

func TestStalledUnbindDeliveryDoesNotBlockUnrelatedPolicySave(t *testing.T) {
	h, b := newSingleBinding(t)
	stalled := &stalledStream{started: make(chan struct{}), release: make(chan struct{})}
	session := &agentSession{controller: h.controller, agent: b.Agent, conn: protocol.NewConn(stalled)}
	h.controller.hub.mu.Lock()
	h.controller.hub.sessions[b.Agent] = session
	h.controller.hub.mu.Unlock()
	defer func() {
		h.controller.hub.mu.Lock()
		delete(h.controller.hub.sessions, b.Agent)
		h.controller.hub.mu.Unlock()
	}()
	done := make(chan struct{})
	go func() { _ = h.controller.DeleteBinding(context.Background(), b.ID, "operator-1"); close(done) }()
	defer func() { close(stalled.release); <-done }()
	<-stalled.started
	saved := make(chan error, 1)
	go func() {
		_, err := h.controller.SavePolicy(context.Background(), policy.New("unrelated", policy.StarterHCL), "operator-1")
		saved <- err
	}()
	select {
	case err := <-saved:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("stalled unbind blocked unrelated policy save")
	}
}

type stalledStream struct {
	started, release chan struct{}
	once             sync.Once
}

func (stream *stalledStream) Read([]byte) (int, error) { return 0, io.EOF }
func (stream *stalledStream) Write(p []byte) (int, error) {
	stream.once.Do(func() { close(stream.started) })
	<-stream.release
	return len(p), nil
}

func newSingleBinding(t *testing.T) (*harness, store.Binding) {
	t.Helper()
	ctx := context.Background()
	h := startHarness(t)
	key := newAgentKey(t)
	_, _ = h.dial("host-a", key)
	if err := h.controller.DecideAgent(ctx, gossh.FingerprintSHA256(key.PublicKey()), true, "operator-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.controller.SavePolicy(ctx, policy.New("alpha", policy.StarterHCL), "operator-1"); err != nil {
		t.Fatal(err)
	}
	b, err := h.controller.CreateBinding(ctx, "host-a", protocol.Key{Kind: protocol.KeyName, Value: "example"}, BindingRequest{Policies: []string{"alpha"}}, "operator-1")
	if err != nil {
		t.Fatal(err)
	}
	return h, b
}
