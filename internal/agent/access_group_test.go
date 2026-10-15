// ---
// relationships:
//   verifies:
//     - agent
//     - command-line-interface
// ---

package agent

import (
	"context"
	"strings"
	"testing"

	"github.com/wyrd-company/wyrwood/internal/engine"
	"github.com/wyrd-company/wyrwood/internal/protocol"
)

func TestContainerStatusExplainsUnassignableAccessGroup(t *testing.T) {
	fake, instance := newBoundApp(t)
	container, ok := fake.ByName("app")
	if !ok {
		t.Fatal("fixture container missing")
	}
	group := uint32(1000)
	instance.set.Bindings[0].Policy.Contract.AccessGroup = &group
	instance.canAssign = func(uint32) bool { return false }
	instance.checkLocked(context.Background(), instance.set.Bindings[0], []engine.Container{container})
	listener, err := instance.listenControl()
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var listing Containers
	if err := Query(context.Background(), instance.paths, ControlRequest{Operation: "containers"}, &listing); err != nil {
		t.Fatal(err)
	}
	if len(listing.Containers) != 1 || !strings.Contains(listing.Containers[0].AccessGroupError, "agent user cannot assign group 1000") || !strings.Contains(listing.Containers[0].AccessGroupError, "restart the agent") {
		t.Fatalf("control socket lost access-group diagnostic: %#v", listing)
	}
	instance.canAssign = func(uint32) bool { return true }
	instance.checkLocked(context.Background(), instance.set.Bindings[0], []engine.Container{container})
	if got := instance.ContainerStatuses().Containers[0].AccessGroupError; got != "" {
		t.Fatalf("recovered group error = %q", got)
	}
	// A failure unrelated to the access group must not report membership trouble.
	instance.results["bnd-1"] = protocol.ContractResult{Binding: "bnd-1", Outcome: protocol.OutcomeNonConforming, FailedItems: []protocol.FailedItem{protocol.FailedMount}}
	if got := instance.ContainerStatuses().Containers[0].AccessGroupError; got != "" {
		t.Fatalf("mount failure group error = %q", got)
	}
}
