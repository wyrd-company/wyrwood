// ---
// relationships:
//
//	verifies: agent-controller-protocol
//
// ---
package controller

import (
	"context"
	gossh "golang.org/x/crypto/ssh"
	"reflect"
	"strings"
	"testing"

	"github.com/wyrd-company/wyrwood/internal/policy"
	"github.com/wyrd-company/wyrwood/internal/protocol"
)

func TestAccessGroupsFollowSessionAuthority(t *testing.T) {
	c := &Controller{}
	c.hub = newHub(c)
	group := uint32(0)
	if err := c.validateAccessGroup("host-a", &group); err != nil {
		t.Fatal(err)
	}
	c.hub.sessions["host-a"] = &agentSession{groups: &protocol.AssignableGroups{Groups: []protocol.Group{{GID: 987}}}}
	if err := c.validateAccessGroup("host-a", &group); err == nil || !strings.Contains(err.Error(), "restart") {
		t.Fatalf("invalid = %v", err)
	}
	if err := c.validateAccessGroup("host-a", nil); err != nil {
		t.Fatal(err)
	}
	group = 987
	if err := c.validateAccessGroup("host-a", &group); err != nil {
		t.Fatal(err)
	}
	group = 1234
	c.hub.sessions["host-a"] = &agentSession{groups: &protocol.AssignableGroups{Groups: []protocol.Group{{GID: 987}, {GID: 1234}}}}
	if err := c.validateAccessGroup("host-a", &group); err != nil {
		t.Fatal(err)
	}
	c.hub.sessions["host-a"] = &agentSession{} // older agent replaces report
	if c.AssignableGroups("host-a") != nil {
		t.Fatal("stale capability retained")
	}
	delete(c.hub.sessions, "host-a")
	if c.AssignableGroups("host-a") != nil {
		t.Fatal("offline capability retained")
	}
}

func TestBindingMutationsRejectKnownUnassignableGroupsBeforeWrites(t *testing.T) {
	h := startHarness(t)
	c := h.controller
	key := newAgentKey(t)
	_, _ = h.dial("host-a", key)
	if err := c.DecideAgent(context.Background(), gossh.FingerprintSHA256(key.PublicKey()), true, "operator-1"); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := c.SavePolicy(ctx, policy.New("sample", policy.StarterHCL), "operator-1"); err != nil {
		t.Fatal(err)
	}
	b, err := c.CreateBinding(ctx, "host-a", protocol.Key{Kind: protocol.KeyName, Value: "sample"}, BindingRequest{Policies: []string{"sample"}}, "operator-1")
	if err != nil {
		t.Fatal(err)
	}
	c.hub.sessions["host-a"] = &agentSession{groups: &protocol.AssignableGroups{Groups: []protocol.Group{{GID: 987}}}}
	defer delete(c.hub.sessions, "host-a")
	// Call the mutation internals to avoid a policy push to this synthetic session.
	zero := uint32(0)
	req := BindingRequest{Policies: []string{"sample"}, Settings: policy.Settings{AccessGroup: &zero}, Revision: b.Revision}
	if _, err := c.createBinding(ctx, "host-a", protocol.Key{Kind: protocol.KeyName, Value: "other"}, req, "operator-1"); err == nil || !strings.Contains(err.Error(), "cannot assign group 0") {
		t.Fatalf("create: %v", err)
	}
	if _, err := c.changeBinding(ctx, b.ID, req, "operator-1"); err == nil || !strings.Contains(err.Error(), "cannot assign group 0") {
		t.Fatalf("change: %v", err)
	}
	saved, err := c.store.Binding(ctx, b.ID)
	if err != nil || saved.Revision != b.Revision || saved.Settings.AccessGroup != nil {
		t.Fatalf("changed: %+v %v", saved, err)
	}
	bindings, err := c.store.Bindings(ctx, "host-a")
	if err != nil || len(bindings) != 1 {
		t.Fatalf("bindings: %+v %v", bindings, err)
	}
	valid := uint32(987)
	req.Settings.AccessGroup = &valid
	created, err := c.createBinding(ctx, "host-a", protocol.Key{Kind: protocol.KeyName, Value: "other"}, req, "operator-1")
	if err != nil || created.Settings.AccessGroup == nil || *created.Settings.AccessGroup != 987 {
		t.Fatalf("valid group not saved: %+v %v", created, err)
	}
	req.Settings.AccessGroup = nil
	if _, err := c.changeBinding(ctx, b.ID, req, "operator-1"); err != nil {
		t.Fatalf("owner-only rejected: %v", err)
	}
	delete(c.hub.sessions, "host-a")
}

func TestGroupReportReplacedByRestartAndOlderAgent(t *testing.T) {
	ctx := context.Background()
	h := startHarness(t)
	key := newAgentKey(t)
	_, _ = h.dial("host-a", key)
	if err := h.controller.DecideAgent(ctx, gossh.FingerprintSHA256(key.PublicKey()), true, "operator-1"); err != nil {
		t.Fatal(err)
	}
	reports := []*protocol.AssignableGroups{
		{Groups: []protocol.Group{{GID: 987}}},
		{Groups: []protocol.Group{{GID: 987}, {GID: 1234}}},
		nil,
	}
	for _, report := range reports {
		conn, err := h.dial("host-a", key)
		if err != nil {
			t.Fatal(err)
		}
		if err := conn.conn.Send(protocol.Hello{AssignableGroups: report}); err != nil {
			t.Fatal(err)
		}
		if err := conn.conn.Send(protocol.Inventory{}); err != nil {
			t.Fatal(err)
		}
		if _, ok := conn.receive(t).(protocol.PolicySet); !ok {
			t.Fatal("no policy set")
		}
		got := h.controller.AssignableGroups("host-a")
		if !reflect.DeepEqual(got, report) {
			t.Fatalf("report = %+v, want %+v", got, report)
		}
		conn.client.Close()
	}
}
