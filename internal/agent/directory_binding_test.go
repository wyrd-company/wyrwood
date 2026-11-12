// ---
// relationships:
//   verifies:
//     - agent
//     - agent-controller-protocol
// ---

package agent

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wyrd-company/wyrwood/internal/consumer"
	"github.com/wyrd-company/wyrwood/internal/engine"
	"github.com/wyrd-company/wyrwood/internal/engine/enginetest"
	"github.com/wyrd-company/wyrwood/internal/events"
	"github.com/wyrd-company/wyrwood/internal/policy"
	"github.com/wyrd-company/wyrwood/internal/protocol"
)

func shopKey() protocol.Key { return protocol.Key{Kind: protocol.KeyCompose, Value: "shop/web"} }

func directoryBinding(directory string) protocol.Binding {
	bound := preparedBinding(shopKey(), policy.DefaultSettings())
	bound.Directory = directory
	return bound
}

// shopContainer is a Compose service container that carries shopKey, mounts
// source at the contract's target, and sets the contract's environment.
func shopContainer(bound protocol.Binding, name, source string) engine.Container {
	container := engine.Container{Name: "/" + name}
	container.State.Status = "running"
	container.Config.Labels = map[string]string{"com.docker.compose.project": "shop", "com.docker.compose.service": "web"}
	for _, entry := range bound.Policy.Contract.ExpandedEnv() {
		container.Config.Env = append(container.Config.Env, entry.Name+"="+entry.Value)
	}
	container.Mounts = []engine.Mount{{Type: "bind", Source: source, Destination: bound.Policy.Contract.MountTarget}}
	return container
}

// A binding whose key is not name, with a directory, prepares that directory
// and its sockets before any container exists, and asks for no token.
func TestDirectoryBindingPrepares(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	instance := newRecreateAgent(t, enginetest.New())
	var requests atomic.Int32
	instance.creds.request = func(string) { requests.Add(1) }
	instance.creds.retryDelay = time.Millisecond
	bound := directoryBinding("shop-web")
	instance.applyPolicySet(ctx, preparedSet("http://127.0.0.1:1", bound))

	path := instance.root.DirectoryPath("shop-web")
	for _, name := range []string{consumer.VaultSocket, consumer.SSHAgentSocket} {
		if got := probe(t, filepath.Join(path, name)); !strings.HasPrefix(got, "example false") {
			t.Fatalf("socket %s = %q", name, got)
		}
	}
	status := onlyStatus(t, instance)
	if status.Token != protocol.TokenNone || len(status.Consumers) != 1 || status.Consumers[0].Directory != path ||
		status.Consumers[0].ContainerID != "" || status.Consumers[0].Failed != "" || !slices.Equal(status.Consumers[0].Sockets, protocol.Sockets) {
		t.Fatalf("status = %#v", status)
	}
	time.Sleep(50 * time.Millisecond)
	if got := requests.Load(); got != 0 {
		t.Fatalf("credential requests with no container = %d", got)
	}
}

// Every container the binding governs uses the stored directory, not one named
// after the container. A removal revokes the token and keeps the directory.
func TestDirectoryBindingServesItsContainer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	openBao := newFakeOpenBao(t)
	engineFake := enginetest.New()
	instance := newRecreateAgent(t, engineFake)
	var requests atomic.Int32
	instance.creds.request = func(string) { requests.Add(1) }
	instance.creds.retryDelay = 5 * time.Millisecond
	bound := directoryBinding("shop-web")
	instance.applyPolicySet(ctx, preparedSet(openBao.server.URL, bound))
	path := instance.root.DirectoryPath("shop-web")
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	engineFake.Add(shopContainer(bound, "shop-web-1", path))
	added, _ := engineFake.ByName("shop-web-1")
	instance.reconcileContainer(ctx, added.ID)
	eventually(t, "a credential request at first observation", func() bool { return requests.Load() >= 1 })
	deliverToken(ctx, t, instance, bound, "role-a")
	if _, err := os.Stat(instance.root.DirectoryPath("shop-web-1")); !os.IsNotExist(err) {
		t.Fatalf("a directory named after the container: %v", err)
	}
	instance.mu.Lock()
	result := instance.results[bound.Binding]
	instance.mu.Unlock()
	if result.Outcome != protocol.OutcomeConforming {
		t.Fatalf("contract result = %#v", result)
	}
	if inventory := instance.inventory(); len(inventory.Containers) != 1 || inventory.Containers[0].ConsumerDirectory != path {
		t.Fatalf("inventory = %#v", inventory)
	}
	status := onlyStatus(t, instance)
	if status.Token != protocol.TokenValid || len(status.Consumers) != 1 || status.Consumers[0].Directory != path || status.Consumers[0].ContainerID != added.ID {
		t.Fatalf("status = %#v", status)
	}

	engineFake.Destroy(added.ID)
	instance.reconcileContainer(ctx, added.ID)
	if heldValue(instance.creds, bound.Binding) != "" {
		t.Fatal("token held with no container")
	}
	eventually(t, "the revoked token", func() bool {
		openBao.mu.Lock()
		defer openBao.mu.Unlock()
		return slices.Contains(openBao.revoked, "token-role-a")
	})
	after, err := os.Stat(path)
	if err != nil || !os.SameFile(before, after) {
		t.Fatalf("consumer directory changed at removal: %v", err)
	}
	if got := probe(t, filepath.Join(path, consumer.VaultSocket)); !strings.HasPrefix(got, "example false") {
		t.Fatalf("socket after removal = %q", got)
	}
	for _, event := range instance.events.Recent(100) {
		if event.Operation == events.OperationBindingRetired {
			t.Fatal("removing the container retired a binding the controller still holds")
		}
	}
}

// A binding's directory belongs to it alone. A container whose name is that
// directory, governed by another binding, gets no consumer directory there.
func TestDirectoryBelongsToItsBinding(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	engineFake := enginetest.New()
	instance := newRecreateAgent(t, engineFake)
	owner := directoryBinding("shared")
	other := preparedBinding(protocol.Key{Kind: protocol.KeyDevcontainer, Value: "/src/app"}, policy.DefaultSettings())
	other.Binding = "bnd-2"
	container := engine.Container{Name: "/shared"}
	container.State.Status = "running"
	container.Config.Labels = map[string]string{"devcontainer.local_folder": "/src/app"}
	engineFake.Add(container)
	if err := instance.fullReconcile(ctx); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		instance.applyPolicySet(ctx, preparedSet("http://127.0.0.1:1", owner, other))
		instance.mu.Lock()
		state := instance.consumers["shared"]
		result := instance.results[other.Binding]
		instance.mu.Unlock()
		if state == nil || state.binding != owner.Binding {
			t.Fatalf("consumer shared = %#v", state)
		}
		if result.Outcome != protocol.OutcomeNonConforming || !slices.Contains(result.FailedItems, protocol.FailedConsumerDirectory) {
			t.Fatalf("result of the other binding = %#v", result)
		}
	}
}
