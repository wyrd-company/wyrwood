// ---
// relationships:
//   implements: linux-per-user-agent-proxy
// ---

package runtime

import (
	"fmt"
	"sync"
	"testing"
)

func TestSnapshotOwnsConfigurationData(t *testing.T) {
	t.Parallel()

	configuration := testConfiguration("alpha")
	store, err := NewStore(configuration)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}

	configuration.Upstream = "/run/mutated/upstream.sock"
	configuration.Consumers[0].Name = "mutated"
	configuration.Consumers[0].Fingerprints[0] = testFingerprint(99)
	*configuration.Consumers[0].AccessGroup = 999

	snapshot := store.Active()
	copy := snapshot.Config()
	copy.Upstream = "/run/copy/upstream.sock"
	copy.Consumers[0].Name = "copy"
	copy.Consumers[0].Fingerprints[0] = testFingerprint(98)
	*copy.Consumers[0].AccessGroup = 998

	consumer, exists := snapshot.Consumer("/run/alpha/agent.sock")
	if !exists {
		t.Fatal("Snapshot.Consumer() exists = false")
	}
	if snapshot.Upstream() != "/run/upstream/agent.sock" {
		t.Fatalf("Snapshot.Upstream() = %q", snapshot.Upstream())
	}
	if consumer.Name() != "alpha" {
		t.Fatalf("Consumer.Name() = %q", consumer.Name())
	}
	if group, ok := consumer.AccessGroup(); !ok || group != 1200 {
		t.Fatalf("Consumer.AccessGroup() = %d, %t", group, ok)
	}
	if !consumer.Policy().Allows(testFingerprint(1)) {
		t.Fatal("Consumer.Policy().Allows(original) = false")
	}
	if consumer.Policy().Allows(testFingerprint(99)) {
		t.Fatal("Consumer.Policy().Allows(mutated) = true")
	}
}

func TestPrepareRejectsInvalidConfigurationWithoutPublishing(t *testing.T) {
	t.Parallel()

	store, err := NewStore(testConfiguration("alpha"))
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	want := store.Active()

	invalid := testConfiguration("beta")
	invalid.Consumers[0].Fingerprints = []string{"*"}
	if _, err := store.Prepare(invalid); err == nil {
		t.Fatal("Store.Prepare() error = nil")
	}
	if got := store.Active(); got != want {
		t.Fatal("Store.Active() changed after failed preparation")
	}
	if policy, exists := store.Policy("/run/alpha/agent.sock"); !exists || !policy.Allows(testFingerprint(1)) {
		t.Fatal("Store.Policy() did not retain the active exact policy")
	}
}

func TestCommitRejectsStalePreparedApply(t *testing.T) {
	t.Parallel()

	store, err := NewStore(testConfiguration("alpha"))
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	stale, err := store.Prepare(testConfiguration("beta"))
	if err != nil {
		t.Fatalf("Store.Prepare(stale) error = %v", err)
	}
	current, err := store.Prepare(testConfiguration("gamma"))
	if err != nil {
		t.Fatalf("Store.Prepare(current) error = %v", err)
	}
	if err := store.Commit(current); err != nil {
		t.Fatalf("Store.Commit(current) error = %v", err)
	}
	if err := store.Commit(stale); err != ErrStaleApply {
		t.Fatalf("Store.Commit(stale) error = %v, want %v", err, ErrStaleApply)
	}
	if _, exists := store.Policy("/run/gamma/agent.sock"); !exists {
		t.Fatal("Store.Policy(gamma) exists = false")
	}
	if _, exists := store.Policy("/run/beta/agent.sock"); exists {
		t.Fatal("Store.Policy(beta) exists = true")
	}
}

func TestConcurrentReadersSeeOnlyCompleteSnapshots(t *testing.T) {
	store, err := NewStore(testConfiguration("alpha"))
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}

	const readerCount = 16
	const replacements = 500
	start := make(chan struct{})
	errors := make(chan error, readerCount)
	var readers sync.WaitGroup
	for range readerCount {
		readers.Add(1)
		go func() {
			defer readers.Done()
			<-start
			for range replacements * 4 {
				snapshot := store.Active()
				configuration := snapshot.Config()
				if len(configuration.Consumers) != 1 {
					errors <- fmt.Errorf("consumer count = %d", len(configuration.Consumers))
					return
				}
				consumer := configuration.Consumers[0]
				wantSocket := "/run/" + consumer.Name + "/agent.sock"
				if consumer.Socket != wantSocket {
					errors <- fmt.Errorf("consumer %q socket = %q", consumer.Name, consumer.Socket)
					return
				}
				wantFingerprint := testFingerprint(1)
				if consumer.Name == "beta" {
					wantFingerprint = testFingerprint(2)
				}
				policy, exists := snapshot.Policy(consumer.Socket)
				if !exists || !policy.Allows(wantFingerprint) || policy.Allows(testFingerprint(3)) {
					errors <- fmt.Errorf("consumer %q policy is partial", consumer.Name)
					return
				}
			}
		}()
	}

	close(start)
	for index := range replacements {
		name := "alpha"
		if index%2 == 0 {
			name = "beta"
		}
		prepared, err := store.Prepare(testConfiguration(name))
		if err != nil {
			t.Fatalf("Store.Prepare(%s) error = %v", name, err)
		}
		if err := store.Commit(prepared); err != nil {
			t.Fatalf("Store.Commit(%s) error = %v", name, err)
		}
	}
	readers.Wait()
	close(errors)
	for err := range errors {
		t.Error(err)
	}
}

func TestConcurrentPolicyReplacementNeverCombinesAllowlists(t *testing.T) {
	store, err := NewStore(testConfiguration("alpha"))
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}

	const readerCount = 16
	const replacements = 500
	first := testFingerprint(1)
	second := testFingerprint(2)
	start := make(chan struct{})
	errors := make(chan error, readerCount)
	var readers sync.WaitGroup
	for range readerCount {
		readers.Add(1)
		go func() {
			defer readers.Done()
			<-start
			for range replacements * 4 {
				policy, exists := store.Policy("/run/alpha/agent.sock")
				if !exists {
					errors <- fmt.Errorf("policy does not exist")
					return
				}
				allowsFirst := policy.Allows(first)
				allowsSecond := policy.Allows(second)
				if allowsFirst == allowsSecond {
					errors <- fmt.Errorf("policy allows first=%t second=%t", allowsFirst, allowsSecond)
					return
				}
			}
		}()
	}

	close(start)
	for index := range replacements {
		next := testConfiguration("alpha")
		if index%2 == 0 {
			next.Consumers[0].Fingerprints = []string{second}
		}
		prepared, err := store.Prepare(next)
		if err != nil {
			t.Fatalf("Store.Prepare() error = %v", err)
		}
		if err := store.Commit(prepared); err != nil {
			t.Fatalf("Store.Commit() error = %v", err)
		}
	}
	readers.Wait()
	close(errors)
	for err := range errors {
		t.Error(err)
	}
}
