// ---
// relationships:
//   implements: linux-per-user-agent-proxy
// ---

package runtime

import (
	"encoding/base64"
	"errors"
	"slices"
	"testing"

	"github.com/wyrd-company/wyrwood/internal/config"
)

func TestPreparePlansConsumersBySocketPath(t *testing.T) {
	t.Parallel()

	initial := testConfiguration("alpha")
	initial.Consumers = append(initial.Consumers,
		testConsumer("retired", 3),
		testConsumer("unchanged", 4),
	)
	store, err := NewStore(initial)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}

	next := testConfiguration("renamed")
	next.Consumers[0].Socket = "/run/alpha/agent.sock"
	next.Consumers[0].Fingerprints = []string{testFingerprint(2), testFingerprint(1)}
	next.Consumers = append(next.Consumers,
		testConsumer("added", 5),
		testConsumer("unchanged", 4),
	)
	prepared, err := store.Prepare(next)
	if err != nil {
		t.Fatalf("Store.Prepare() error = %v", err)
	}

	plan := prepared.Plan()
	if got, want := consumerSockets(plan.Retained()), []string{"/run/unchanged/agent.sock"}; !slices.Equal(got, want) {
		t.Fatalf("Plan.Retained() sockets = %v, want %v", got, want)
	}
	if got, want := consumerSockets(plan.Added()), []string{"/run/added/agent.sock"}; !slices.Equal(got, want) {
		t.Fatalf("Plan.Added() sockets = %v, want %v", got, want)
	}
	if got, want := consumerSockets(plan.Retired()), []string{"/run/retired/agent.sock"}; !slices.Equal(got, want) {
		t.Fatalf("Plan.Retired() sockets = %v, want %v", got, want)
	}
	updates := plan.Updated()
	if len(updates) != 1 {
		t.Fatalf("len(Plan.Updated()) = %d, want 1", len(updates))
	}
	if updates[0].Before().Socket() != "/run/alpha/agent.sock" || updates[0].After().Socket() != "/run/alpha/agent.sock" {
		t.Fatalf("updated socket changed from %q to %q", updates[0].Before().Socket(), updates[0].After().Socket())
	}
	if updates[0].After().Name() != "renamed" {
		t.Fatalf("updated name = %q", updates[0].After().Name())
	}
	if !updates[0].After().Policy().Allows(testFingerprint(1)) || !updates[0].After().Policy().Allows(testFingerprint(2)) {
		t.Fatal("updated policy does not contain the exact replacement allowlist")
	}
	if _, exists := store.Policy("/run/added/agent.sock"); exists {
		t.Fatal("Store changed before Commit")
	}
	if err := store.Commit(prepared); err != nil {
		t.Fatalf("Store.Commit() error = %v", err)
	}
	if policy, exists := store.Policy("/run/alpha/agent.sock"); !exists || !policy.Allows(testFingerprint(2)) {
		t.Fatal("Store.Policy() did not publish the replacement policy")
	}
}

func TestSocketPathChangePlansAdditionAndRetirement(t *testing.T) {
	t.Parallel()

	store, err := NewStore(testConfiguration("alpha"))
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	next := testConfiguration("alpha")
	next.Consumers[0].Socket = "/run/replacement/agent.sock"
	prepared, err := store.Prepare(next)
	if err != nil {
		t.Fatalf("Store.Prepare() error = %v", err)
	}
	plan := prepared.Plan()
	if got, want := consumerSockets(plan.Added()), []string{"/run/replacement/agent.sock"}; !slices.Equal(got, want) {
		t.Fatalf("Plan.Added() sockets = %v, want %v", got, want)
	}
	if got, want := consumerSockets(plan.Retired()), []string{"/run/alpha/agent.sock"}; !slices.Equal(got, want) {
		t.Fatalf("Plan.Retired() sockets = %v, want %v", got, want)
	}
	if len(plan.Updated()) != 0 || len(plan.Retained()) != 0 {
		t.Fatalf("path change plan has %d updates and %d retained", len(plan.Updated()), len(plan.Retained()))
	}
}

func TestPrepareRetainsConsumerWhenOnlyFingerprintOrderChanges(t *testing.T) {
	t.Parallel()

	initial := testConfiguration("alpha")
	initial.Consumers[0].Fingerprints = []string{testFingerprint(1), testFingerprint(2)}
	store, err := NewStore(initial)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}

	next := testConfiguration("alpha")
	next.Consumers[0].Fingerprints = []string{testFingerprint(2), testFingerprint(1)}
	prepared, err := store.Prepare(next)
	if err != nil {
		t.Fatalf("Store.Prepare() error = %v", err)
	}
	plan := prepared.Plan()
	if got := len(plan.Retained()); got != 1 {
		t.Fatalf("len(Plan.Retained()) = %d, want 1", got)
	}
	if got := len(plan.Updated()); got != 0 {
		t.Fatalf("len(Plan.Updated()) = %d, want 0", got)
	}
	policy := plan.Retained()[0].Policy()
	if !policy.Allows(testFingerprint(1)) || !policy.Allows(testFingerprint(2)) {
		t.Fatal("retained policy does not preserve exact allowlist membership")
	}
}

func TestPlanOrderingIsDeterministic(t *testing.T) {
	t.Parallel()

	initial := testConfiguration("delta")
	initial.Consumers = append(initial.Consumers,
		testConsumer("charlie", 3),
		testConsumer("bravo", 2),
		testConsumer("alpha", 1),
	)
	store, err := NewStore(initial)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}

	next := testConfiguration("echo")
	next.Consumers = append(next.Consumers,
		testConsumer("foxtrot", 6),
		testConsumer("bravo", 7),
		testConsumer("alpha", 1),
	)
	prepared, err := store.Prepare(next)
	if err != nil {
		t.Fatalf("Store.Prepare() error = %v", err)
	}
	plan := prepared.Plan()
	if got, want := consumerSockets(plan.Retained()), []string{"/run/alpha/agent.sock"}; !slices.Equal(got, want) {
		t.Fatalf("retained order = %v, want %v", got, want)
	}
	if got, want := consumerSockets(plan.Added()), []string{"/run/echo/agent.sock", "/run/foxtrot/agent.sock"}; !slices.Equal(got, want) {
		t.Fatalf("added order = %v, want %v", got, want)
	}
	if got, want := updatedSockets(plan.Updated()), []string{"/run/bravo/agent.sock"}; !slices.Equal(got, want) {
		t.Fatalf("updated order = %v, want %v", got, want)
	}
	if got, want := consumerSockets(plan.Retired()), []string{"/run/charlie/agent.sock", "/run/delta/agent.sock"}; !slices.Equal(got, want) {
		t.Fatalf("retired order = %v, want %v", got, want)
	}
}

func TestCommitRejectsForeignOrNilPreparedApply(t *testing.T) {
	t.Parallel()

	first, err := NewStore(testConfiguration("alpha"))
	if err != nil {
		t.Fatalf("NewStore(first) error = %v", err)
	}
	second, err := NewStore(testConfiguration("alpha"))
	if err != nil {
		t.Fatalf("NewStore(second) error = %v", err)
	}
	prepared, err := first.Prepare(testConfiguration("beta"))
	if err != nil {
		t.Fatalf("Store.Prepare() error = %v", err)
	}
	if err := second.Commit(prepared); !errors.Is(err, ErrForeignApply) {
		t.Fatalf("Store.Commit(foreign) error = %v, want %v", err, ErrForeignApply)
	}
	if err := first.Commit(nil); !errors.Is(err, ErrForeignApply) {
		t.Fatalf("Store.Commit(nil) error = %v, want %v", err, ErrForeignApply)
	}
}

func testConfiguration(name string) config.Config {
	fingerprint := 1
	if name == "beta" {
		fingerprint = 2
	}
	return config.Config{
		Upstream:  "/run/upstream/agent.sock",
		Consumers: []config.Consumer{testConsumer(name, byte(fingerprint))},
		Timeouts:  config.DefaultTimeouts(),
	}
}

func testConsumer(name string, fingerprint byte) config.Consumer {
	group := uint32(1200)
	return config.Consumer{
		Name:         name,
		Socket:       "/run/" + name + "/agent.sock",
		AccessGroup:  &group,
		Fingerprints: []string{testFingerprint(fingerprint)},
	}
}

func testFingerprint(value byte) string {
	digest := make([]byte, 32)
	for index := range digest {
		digest[index] = value
	}
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(digest)
}

func consumerSockets(consumers []Consumer) []string {
	sockets := make([]string, len(consumers))
	for index, consumer := range consumers {
		sockets[index] = consumer.Socket()
	}
	return sockets
}

func updatedSockets(updates []ConsumerUpdate) []string {
	sockets := make([]string, len(updates))
	for index, update := range updates {
		sockets[index] = update.After().Socket()
	}
	return sockets
}
