// ---
// relationships:
//   verifies:
//     - agent
//     - agent-controller-protocol
// ---

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/wyrd-company/wyrwood/internal/consumer"
	"github.com/wyrd-company/wyrwood/internal/engine"
	"github.com/wyrd-company/wyrwood/internal/engine/enginetest"
	"github.com/wyrd-company/wyrwood/internal/events"
	"github.com/wyrd-company/wyrwood/internal/policy"
	"github.com/wyrd-company/wyrwood/internal/protocol"
)

func preparedSet(address string, bound ...protocol.Binding) protocol.PolicySet {
	return protocol.PolicySet{OpenBao: protocol.OpenBao{Address: address}, Bindings: bound}
}

func preparedBinding(key protocol.Key, settings policy.Settings) protocol.Binding {
	effective := policy.New("example", policy.StarterHCL).Runtime(settings)
	return protocol.Binding{Binding: "bnd-1", Key: key, Policy: effective, Assignment: effective.Identity()}
}

func appKey() protocol.Key { return protocol.Key{Kind: protocol.KeyName, Value: "app"} }

func deliverToken(ctx context.Context, t *testing.T, instance *Agent, bound protocol.Binding, role string) {
	t.Helper()
	credential := credential(bound.Binding, role)
	credential.Assignment = bound.Assignment
	if !instance.receiveCredential(ctx, credential) {
		t.Fatal("credential dropped")
	}
	eventually(t, "the delivered token", func() bool { return heldValue(instance.creds, bound.Binding) == "token-"+role })
}

func TestUnmatchedNameBindingPreparesItsConsumerWithNoToken(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	instance := newRecreateAgent(t, enginetest.New())
	var requests atomic.Int32
	instance.creds.request = func(string) { requests.Add(1) }
	instance.creds.retryDelay = time.Millisecond

	group := uint32(os.Getgid())
	settings := policy.DefaultSettings()
	settings.AccessGroup = &group
	bound := preparedBinding(appKey(), settings)
	instance.applyPolicySet(ctx, preparedSet("http://127.0.0.1:1", bound))

	path := instance.root.DirectoryPath("app")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("consumer directory: %v", err)
	}
	if info.Mode().Perm() != 0o750 || info.Sys().(*syscall.Stat_t).Gid != group {
		t.Fatalf("consumer directory mode %v gid %d", info.Mode().Perm(), info.Sys().(*syscall.Stat_t).Gid)
	}
	for _, name := range []string{consumer.VaultSocket, consumer.SSHAgentSocket} {
		if got := probe(t, filepath.Join(path, name)); !strings.HasPrefix(got, "example false") {
			t.Fatalf("socket %s = %q", name, got)
		}
	}
	// A changed assignment asks for nothing while there is no consumer either.
	settings.TokenTTL = "2h"
	instance.applyPolicySet(ctx, preparedSet("http://127.0.0.1:1", preparedBinding(appKey(), settings)))
	time.Sleep(50 * time.Millisecond)
	if got := requests.Load(); got != 0 {
		t.Fatalf("credential requests with no container = %d", got)
	}
}

func TestCredentialIsDroppedBeforeTheFirstObservation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fake := newFakeOpenBao(t)
	instance := newRecreateAgent(t, enginetest.New())
	bound := preparedBinding(appKey(), policy.DefaultSettings())
	instance.applyPolicySet(ctx, preparedSet(fake.server.URL, bound))
	credential := credential(bound.Binding, "role-a")
	credential.Assignment = bound.Assignment
	if instance.receiveCredential(ctx, credential) {
		t.Fatal("agent started a delivery for a binding with no container")
	}
}

func TestFirstObservationAsksForACredentialAndRemovalRevokes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	openBao := newFakeOpenBao(t)
	engineFake := enginetest.New()
	instance := newRecreateAgent(t, engineFake)
	var requests atomic.Int32
	instance.creds.request = func(string) { requests.Add(1) }
	instance.creds.retryDelay = 5 * time.Millisecond
	bound := preparedBinding(appKey(), policy.DefaultSettings())
	instance.applyPolicySet(ctx, preparedSet(openBao.server.URL, bound))

	path := instance.root.DirectoryPath("app")
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	app := runningApp(engineFake)
	instance.reconcileContainer(ctx, app.ID)
	eventually(t, "a credential request at first observation", func() bool { return requests.Load() >= 1 })
	deliverToken(ctx, t, instance, bound, "role-a")

	engineFake.Destroy(app.ID)
	instance.reconcileContainer(ctx, app.ID)
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
	instance.mu.Lock()
	_, kept := instance.results[bound.Binding]
	instance.mu.Unlock()
	if kept {
		t.Fatal("contract result kept with no container")
	}
	for _, event := range instance.events.Recent(100) {
		if event.Operation == events.OperationBindingRetired {
			t.Fatal("removing the container retired a binding the controller still holds")
		}
	}

	// A later observation under the same name gets a fresh token.
	settled := requests.Load()
	time.Sleep(50 * time.Millisecond)
	if requests.Load() != settled {
		t.Fatal("agent still asks for a credential with no container")
	}
	replacement := runningApp(engineFake)
	instance.reconcileContainer(ctx, replacement.ID)
	eventually(t, "a request for the replacement", func() bool { return requests.Load() > settled })
	deliverToken(ctx, t, instance, bound, "role-b")
}

// The controller withdraws a binding on any other key, as it always did.
func TestOtherKeyKeepsItsTokenUntilTheControllerWithdrawsIt(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	openBao := newFakeOpenBao(t)
	engineFake := enginetest.New()
	compose := engine.Container{Name: "/app"}
	compose.State.Status = "running"
	compose.Config.Labels = map[string]string{"com.docker.compose.project": "shop", "com.docker.compose.service": "app"}
	engineFake.Add(compose)
	added, _ := engineFake.ByName("app")
	instance := newRecreateAgent(t, engineFake)
	if err := instance.fullReconcile(ctx); err != nil {
		t.Fatal(err)
	}
	bound := preparedBinding(protocol.Key{Kind: protocol.KeyCompose, Value: "shop/app"}, policy.DefaultSettings())
	instance.applyPolicySet(ctx, preparedSet(openBao.server.URL, bound))
	deliverToken(ctx, t, instance, bound, "role-a")

	engineFake.Destroy(added.ID)
	instance.reconcileContainer(ctx, added.ID)
	if heldValue(instance.creds, bound.Binding) != "token-role-a" {
		t.Fatal("agent revoked a token the controller did not withdraw")
	}
	// A replacement that arrives before the withdrawal keeps the token too.
	engineFake.Add(compose)
	replacement, _ := engineFake.ByName("app")
	instance.reconcileContainer(ctx, replacement.ID)
	if heldValue(instance.creds, bound.Binding) != "token-role-a" {
		t.Fatal("agent replaced a token it still holds")
	}
	engineFake.Destroy(replacement.ID)
	instance.reconcileContainer(ctx, replacement.ID)
	instance.applyPolicySet(ctx, preparedSet(openBao.server.URL))
	if heldValue(instance.creds, bound.Binding) != "" {
		t.Fatal("withdrawn binding kept its token")
	}
}

func TestRecreateGapKeepsANameBindingToken(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	openBao := newFakeOpenBao(t)
	engineFake := enginetest.New()
	instance := newRecreateAgent(t, engineFake)
	bound := preparedBinding(appKey(), policy.DefaultSettings())
	instance.applyPolicySet(ctx, preparedSet(openBao.server.URL, bound))
	app := runningApp(engineFake)
	instance.reconcileContainer(ctx, app.ID)
	deliverToken(ctx, t, instance, bound, "role-a")

	instance.mu.Lock()
	instance.recreating["app"] = true
	instance.mu.Unlock()
	engineFake.Destroy(app.ID)
	instance.reconcileContainer(ctx, app.ID)
	if heldValue(instance.creds, bound.Binding) != "token-role-a" {
		t.Fatal("recreate gap revoked the token")
	}
	instance.mu.Lock()
	delete(instance.recreating, "app")
	instance.mu.Unlock()
}

// Enforcement waits for the container: a binding that arrived first still
// recreates a non-conforming container once it is observed.
func TestFirstObservationRecreatesANonConformingContainer(t *testing.T) {
	ctx := context.Background()
	engineFake := enginetest.New()
	instance := newRecreateAgent(t, engineFake)
	bound := recreateBinding()
	set := preparedSet("http://127.0.0.1:1", bound)
	instance.applyPolicySet(ctx, set)
	if slices.Contains(engineFake.CallLog(), "remove") {
		t.Fatal("recreate with no container")
	}
	app := runningApp(engineFake)
	instance.reconcileContainer(ctx, app.ID)
	instance.applyPolicySet(ctx, set)
	eventually(t, "the recreate", func() bool {
		replacement, ok := engineFake.ByName("app")
		return ok && replacement.ID != app.ID
	})
}

func TestRestartRestoresAPreparedConsumerFromTheCache(t *testing.T) {
	ctx := context.Background()
	engineFake := enginetest.New()
	first := newRecreateAgent(t, engineFake)
	first.applyPolicySet(ctx, preparedSet("http://127.0.0.1:1", preparedBinding(appKey(), policy.DefaultSettings())))
	path := first.root.DirectoryPath("app")
	first.shutdown()
	if err := os.RemoveAll(path); err != nil {
		t.Fatal(err)
	}
	second := newRecreateAgentAt(t, engineFake, first.paths)
	second.loadCache()
	if err := second.fullReconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if got := probe(t, filepath.Join(path, consumer.VaultSocket)); !strings.HasPrefix(got, "example false") {
		t.Fatalf("restored socket = %q", got)
	}
	if status := second.Status(); status.Bindings != 1 || status.Tokens != 0 {
		t.Fatalf("status = %#v", status)
	}
}

type listFailure struct{ *enginetest.Fake }

func (listFailure) List(context.Context) ([]engine.Summary, error) {
	return nil, errors.New("engine unavailable")
}

// At boot the agent can start before the engine, which needs the mount source.
func TestPreparedConsumerIsRestoredWithTheEngineDown(t *testing.T) {
	first := newRecreateAgent(t, enginetest.New())
	first.applyPolicySet(context.Background(), preparedSet("http://127.0.0.1:1", preparedBinding(appKey(), policy.DefaultSettings())))
	path := first.root.DirectoryPath("app")
	first.shutdown()
	if err := os.RemoveAll(path); err != nil {
		t.Fatal(err)
	}
	second := newRecreateAgentAt(t, listFailure{enginetest.New()}, first.paths)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- second.Run(ctx) }()
	eventually(t, "the restored socket", func() bool {
		return strings.HasPrefix(probe(t, filepath.Join(path, consumer.VaultSocket)), "example false")
	})
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// The cache's known list is what stops a restart from recreating again, so
// a binding that only ever waited must not be in it.
func TestPreparedBindingIsNotRecordedAsKnown(t *testing.T) {
	instance := newRecreateAgent(t, enginetest.New())
	instance.applyPolicySet(context.Background(), preparedSet("http://127.0.0.1:1", recreateBinding()))
	data, err := os.ReadFile(instance.paths.PolicyCache())
	if err != nil {
		t.Fatal(err)
	}
	var cached policyCache
	if err := json.Unmarshal(data, &cached); err != nil {
		t.Fatal(err)
	}
	if len(cached.Set.Bindings) != 1 || len(cached.Bindings) != 0 {
		t.Fatalf("cache = %d bindings, known %v", len(cached.Set.Bindings), cached.Bindings)
	}
}
