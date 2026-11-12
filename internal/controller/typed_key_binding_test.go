// ---
// relationships:
//   verifies:
//     - controller
//     - composable-policy-bindings
// ---

package controller

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/wyrd-company/wyrwood/internal/events"
	"github.com/wyrd-company/wyrwood/internal/policy"
	"github.com/wyrd-company/wyrwood/internal/protocol"
	"github.com/wyrd-company/wyrwood/operator"
)

// connectAgent opens an approved agent session that has reported an empty
// inventory, and returns it after the first policy set.
func (harness *harness) connectAgent(t *testing.T, name string) *agentConnection {
	t.Helper()
	key := harness.approveAgent(t, name)
	connection, err := harness.dial(name, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.client.Close() })
	if err := connection.conn.Send(protocol.Hello{AgentVersion: "test"}); err != nil {
		t.Fatal(err)
	}
	if err := connection.conn.Send(protocol.Inventory{Containers: []protocol.Container{}}); err != nil {
		t.Fatal(err)
	}
	if set, ok := connection.receive(t).(protocol.PolicySet); !ok || len(set.Bindings) != 0 {
		t.Fatalf("first policy set = %#v", set)
	}
	return connection
}

var shopWeb = protocol.Key{Kind: protocol.KeyCompose, Value: "shop/web"}

func sampleSelection() BindingRequest { return BindingRequest{Policies: []string{"sample"}} }

// within polls condition until it holds or ten seconds pass.
func within(t *testing.T, what string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatalf("%s did not happen", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// The operator protocol has no directory input. Its bind of a key that is not
// name, for a container no agent reports, keeps the behavior it had: the
// binding is stored with no directory, and it waits for the container with
// nothing prepared.
func TestOperatorBindOfAnUnreportedComposeKeyWaitsForItsContainer(t *testing.T) {
	ctx := context.Background()
	harness := startHarness(t)
	connection := harness.connectAgent(t, "sample-host")
	harness.savePolicy(t, "sample")
	client, _ := harness.approvedOperator(t, "sample-operator", fullGrant)
	bound, err := client.Bind(ctx, operator.BindRequest{Agent: "sample-host", Key: operator.Key{Kind: operator.KeyCompose, Value: "shop/web"}, Policies: []string{"sample"}})
	if err != nil || bound.Key.Kind != operator.KeyCompose || bound.Status.Readiness != operator.ReadinessWaiting ||
		!slices.Equal(bound.Status.Reasons, []string{"container"}) || len(bound.Status.Consumers) != 0 {
		t.Fatalf("Bind() = %+v, %v", bound, err)
	}
	stored, err := harness.controller.Store().Binding(ctx, bound.ID)
	if err != nil || stored.Key != shopWeb || stored.Directory != "" {
		t.Fatalf("Binding() = %+v, %v", stored, err)
	}
	if set, ok := connection.receive(t).(protocol.PolicySet); !ok || len(set.Bindings) != 0 {
		t.Fatalf("policy set after the bind = %#v", set)
	}
}

// A key that is not name, for a container no agent reports, needs a directory
// name. With one, the binding reaches the agent before its container exists,
// and no credential is issued for it.
func TestATypedKeyBindingNeedsADirectoryUntilItsContainerIsReported(t *testing.T) {
	ctx := context.Background()
	harness := startHarness(t)
	connection := harness.connectAgent(t, "sample-host")
	harness.savePolicy(t, "sample")
	c := harness.controller

	_, err := c.CreateBindingFor(ctx, BindingTarget{Agent: "sample-host", Key: shopWeb}, sampleSelection(), "operator-1")
	var operation *OperationError
	if !errors.Is(err, ErrDirectoryRequired) || !errors.As(err, &operation) || operation.Part != policy.PartKey || operation.Code != events.ErrorPolicyDenied {
		t.Fatalf("CreateBindingFor() with no directory = %v", err)
	}
	if bindings, err := c.Store().Bindings(ctx, "sample-host"); err != nil || len(bindings) != 0 {
		t.Fatalf("bindings after the refusal = %v, %v", bindings, err)
	}
	refused := false
	for _, event := range c.Events().Recent(100) {
		if event.Operation == events.OperationBindingCreated && event.Outcome == events.OutcomeDenied && event.Operator == "operator-1" && event.Agent == "sample-host" {
			refused = true
		}
	}
	if !refused {
		t.Fatal("the refusal recorded no binding-created event")
	}

	bound, err := c.CreateBindingFor(ctx, BindingTarget{Agent: "sample-host", Key: shopWeb, Directory: "shop-web"}, sampleSelection(), "operator-1")
	if err != nil || bound.Directory != "shop-web" {
		t.Fatalf("CreateBindingFor() = %+v, %v", bound, err)
	}
	stored, err := c.Store().Binding(ctx, bound.ID)
	if err != nil || stored.Directory != "shop-web" {
		t.Fatalf("Binding() = %+v, %v", stored, err)
	}
	set, ok := connection.receive(t).(protocol.PolicySet)
	if !ok || len(set.Bindings) != 1 || set.Bindings[0].Binding != bound.ID || set.Bindings[0].Directory != "shop-web" || set.Bindings[0].Key != shopWeb {
		t.Fatalf("policy set = %#v", set)
	}
	// Readiness waits for the agent's report, which then shows the directory.
	status, err := c.BindingStatus(ctx, bound.ID)
	if err != nil || status.Readiness != ReadinessWaiting || !slices.Equal(status.Reasons, []NotReadyReason{ReasonAgentReport}) {
		t.Fatalf("status before the agent's report = %+v, %v", status, err)
	}
	directory := "/run/wyrwood/containers/shop-web"
	send := func(message protocol.Message) {
		t.Helper()
		if err := connection.conn.Send(message); err != nil {
			t.Fatal(err)
		}
	}
	send(protocol.BindingStatus{Binding: bound.ID, Assignment: bound.Assignment(), Token: protocol.TokenNone,
		Consumers: []protocol.ConsumerStatus{{Directory: directory, Sockets: protocol.Sockets}}})
	within(t, "the reported directory", func() bool {
		status, err = c.BindingStatus(ctx, bound.ID)
		return err == nil && len(status.Consumers) == 1
	})
	if status.Readiness != ReadinessWaiting || !slices.Contains(status.Reasons, ReasonNoContainer) || status.Consumers[0].Directory != directory {
		t.Fatalf("status with the prepared directory = %+v", status)
	}
	// A credential request before the container is answered with nothing: the
	// next message is the set for the following inventory.
	send(protocol.CredentialRequest{Binding: bound.ID})
	send(protocol.Inventory{Containers: []protocol.Container{}})
	if _, ok := connection.receive(t).(protocol.PolicySet); !ok {
		t.Fatal("the agent received something other than a policy set")
	}

	// A reported container with the key needs no directory name.
	other := protocol.Key{Kind: protocol.KeyCompose, Value: "shop/api"}
	send(protocol.Inventory{Containers: []protocol.Container{{ID: strings.Repeat("a", 64), Name: "shop-api-1", State: protocol.StateRunning, Keys: []protocol.Key{other}}}})
	within(t, "the stored inventory", func() bool {
		containers, _, err := c.Store().Inventory(ctx, "sample-host")
		return err == nil && len(containers) == 1
	})
	reported, err := c.CreateBindingFor(ctx, BindingTarget{Agent: "sample-host", Key: other}, sampleSelection(), "operator-1")
	if err != nil || reported.Directory != "" {
		t.Fatalf("CreateBindingFor() for a reported key = %+v, %v", reported, err)
	}
}

// Each refusal of a directory name is named, and leaves no binding. The other
// fields are valid, so that only the directory can refuse.
func TestDirectoryNameRefusals(t *testing.T) {
	ctx := context.Background()
	harness := startHarness(t)
	harness.approveAgent(t, "sample-host")
	harness.savePolicy(t, "sample")
	c := harness.controller
	if _, err := c.CreateBindingFor(ctx, BindingTarget{Agent: "sample-host", Key: shopWeb, Directory: "taken"}, sampleSelection(), "operator-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.CreateBindingFor(ctx, BindingTarget{Agent: "sample-host", Key: protocol.Key{Kind: protocol.KeyName, Value: "named"}}, sampleSelection(), "operator-1"); err != nil {
		t.Fatal(err)
	}
	devcontainer := protocol.Key{Kind: protocol.KeyDevcontainer, Value: "/src/app"}
	for name, test := range map[string]struct {
		target BindingTarget
		want   error
	}{
		"separator":   {BindingTarget{Key: devcontainer, Directory: "a/b"}, protocol.ErrDirectoryNameSeparator},
		"parent":      {BindingTarget{Key: devcontainer, Directory: ".."}, protocol.ErrDirectoryNameDots},
		"current":     {BindingTarget{Key: devcontainer, Directory: "."}, protocol.ErrDirectoryNameDots},
		"length":      {BindingTarget{Key: devcontainer, Directory: strings.Repeat("a", 256)}, protocol.ErrDirectoryNameLength},
		"characters":  {BindingTarget{Key: devcontainer, Directory: "web app"}, protocol.ErrDirectoryNameCharacters},
		"empty":       {BindingTarget{Key: devcontainer}, ErrDirectoryRequired},
		"name-key":    {BindingTarget{Key: protocol.Key{Kind: protocol.KeyName, Value: "web"}, Directory: "web"}, protocol.ErrDirectoryNameForName},
		"in-use":      {BindingTarget{Key: devcontainer, Directory: "taken"}, ErrDirectoryInUse},
		"name-in-use": {BindingTarget{Key: devcontainer, Directory: "named"}, ErrDirectoryInUse},
		"name-taken":  {BindingTarget{Key: protocol.Key{Kind: protocol.KeyName, Value: "taken"}}, ErrDirectoryInUse},
	} {
		t.Run(name, func(t *testing.T) {
			test.target.Agent = "sample-host"
			_, err := c.CreateBindingFor(ctx, test.target, sampleSelection(), "operator-1")
			var operation *OperationError
			if !errors.Is(err, test.want) || !errors.As(err, &operation) || operation.Part != policy.PartKey {
				t.Fatalf("CreateBindingFor(%q) = %v, want %v", test.target.Directory, err, test.want)
			}
			if bindings, err := c.Store().Bindings(ctx, "sample-host"); err != nil || len(bindings) != 2 {
				t.Fatalf("bindings after the refusal = %d, %v", len(bindings), err)
			}
		})
	}
	// The in-use rule is per agent.
	harness.approveAgent(t, "other-host")
	if _, err := c.CreateBindingFor(ctx, BindingTarget{Agent: "other-host", Key: shopWeb, Directory: "taken"}, sampleSelection(), "operator-1"); err != nil {
		t.Fatalf("the directory on another agent = %v", err)
	}
}
