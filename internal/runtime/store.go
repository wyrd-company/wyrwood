// ---
// relationships:
//   implements: linux-per-user-agent-proxy
// ---

package runtime

import (
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/wyrd-company/wyrwood/internal/config"
)

var (
	// ErrStaleApply means the active snapshot changed after preparation.
	ErrStaleApply = errors.New("prepared apply is stale")
	// ErrForeignApply means the preparation did not originate from this store.
	ErrForeignApply = errors.New("prepared apply does not belong to this store")
)

// Store publishes one complete immutable active snapshot to concurrent readers.
type Store struct {
	active atomic.Pointer[Snapshot]
}

// PreparedApply holds a validated candidate snapshot and its reconciliation plan.
// It performs no listener or upstream I/O.
type PreparedApply struct {
	store *Store
	base  *Snapshot
	next  *Snapshot
	plan  Plan
}

// NewStore validates and publishes an initial complete configuration.
func NewStore(initial config.Config) (*Store, error) {
	snapshot, err := newSnapshot(initial)
	if err != nil {
		return nil, fmt.Errorf("create initial runtime snapshot: %w", err)
	}
	store := &Store{}
	store.active.Store(snapshot)
	return store, nil
}

// Active returns the immutable snapshot active at the instant of the call.
func (store *Store) Active() *Snapshot {
	return store.active.Load()
}

// Policy looks up the current exact policy at request time by socket identity.
func (store *Store) Policy(socket string) (Policy, bool) {
	return store.Active().Policy(socket)
}

// Prepare validates and owns a complete replacement configuration, then plans
// reconciliation against the current snapshot without changing active state.
func (store *Store) Prepare(configuration config.Config) (*PreparedApply, error) {
	base := store.Active()
	next, err := newSnapshot(configuration)
	if err != nil {
		return nil, fmt.Errorf("prepare runtime snapshot: %w", err)
	}
	return &PreparedApply{
		store: store,
		base:  base,
		next:  next,
		plan:  buildPlan(base, next),
	}, nil
}

// Plan returns the immutable deterministic reconciliation plan.
func (prepared *PreparedApply) Plan() Plan {
	return prepared.plan
}

// Snapshot returns the immutable validated candidate snapshot.
func (prepared *PreparedApply) Snapshot() *Snapshot {
	return prepared.next
}

// Commit atomically publishes the complete candidate if its base remains active.
func (store *Store) Commit(prepared *PreparedApply) error {
	if prepared == nil || prepared.store != store {
		return ErrForeignApply
	}
	if !store.active.CompareAndSwap(prepared.base, prepared.next) {
		return ErrStaleApply
	}
	return nil
}
