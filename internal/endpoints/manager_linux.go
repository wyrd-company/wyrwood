//go:build linux

// ---
// relationships:
//   implements: linux-per-user-agent-proxy
// ---

// Package endpoints owns Linux AF_UNIX consumer listeners and transactional
// reconciliation of those listeners with immutable runtime configuration.
package endpoints

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wyrd-company/wyrwood/internal/config"
	"github.com/wyrd-company/wyrwood/internal/events"
	"github.com/wyrd-company/wyrwood/internal/runtime"
)

const defaultCleanupRetryInterval = time.Second

var ErrClosed = errors.New("consumer endpoint manager is closed")

// EventSink accepts closed, non-sensitive operational events.
type EventSink interface {
	Append(events.Event) error
}

// ApplyResult reports whether a complete snapshot was published and whether
// post-commit work still leaves endpoint health degraded.
type ApplyResult struct {
	Committed          bool
	Degraded           bool
	PendingCleanup     int
	PendingPermissions int
}

// Health reports only bounded categorical reconciliation state.
type Health struct {
	Degraded           bool
	PendingCleanup     int
	PendingPermissions int
	EventSinkError     bool
	ListenerError      bool
}

// ConsumerStatus is a bounded, path-free view of one active endpoint.
type ConsumerStatus struct {
	ID                string
	Name              string
	Listening         bool
	ActiveConnections int
}

// Manager owns every active consumer listener for one daemon process.
type Manager struct {
	applyMu sync.Mutex
	store   *runtime.Store
	sink    EventSink
	deps    dependencies

	active             map[string]*endpoint
	pending            map[string]*pendingCleanup
	pendingPermissions map[string]*pendingPermission
	closed             bool

	eventSinkError     atomic.Bool
	listenerError      atomic.Bool
	transientListeners atomic.Int64
	stopRetry          chan struct{}
	retryDone          chan struct{}
}

type dependencies struct {
	prepareSocket    func(runtime.Consumer) (*stagedSocket, error)
	prepareActive    func(runtime.Consumer, *endpointFile, bool) (*metadataChange, error)
	removeSocket     func(*endpointFile) error
	applyPermissions func(*metadataChange) error
	accept           func(*net.UnixListener) (*net.UnixConn, error)
	now              func() time.Time
	retryInterval    time.Duration
	beforeCommit     func()
}

type pendingCleanup struct {
	file       *endpointFile
	consumerID events.ConsumerID
}

type pendingPermission struct {
	change     *metadataChange
	consumerID events.ConsumerID
}

func defaultDependencies() dependencies {
	return dependencies{
		prepareSocket:    prepareSocket,
		prepareActive:    prepareActiveSocket,
		removeSocket:     removeSocket,
		applyPermissions: func(change *metadataChange) error { return change.commit() },
		accept:           func(listener *net.UnixListener) (*net.UnixConn, error) { return listener.AcceptUnix() },
		now:              time.Now,
		retryInterval:    defaultCleanupRetryInterval,
	}
}

// Open prepares and publishes an initial complete configuration. The event
// sink is required because endpoint lifecycle is part of operational health.
func Open(initial config.Config, sink EventSink) (*Manager, error) {
	return openWithDependencies(initial, sink, defaultDependencies())
}

func openWithDependencies(initial config.Config, sink EventSink, deps dependencies) (*Manager, error) {
	if sink == nil {
		return nil, errors.New("operational event sink is required")
	}
	if deps.prepareSocket == nil || deps.prepareActive == nil || deps.removeSocket == nil || deps.applyPermissions == nil || deps.accept == nil || deps.now == nil {
		return nil, errors.New("endpoint dependencies are incomplete")
	}
	if deps.retryInterval <= 0 {
		return nil, errors.New("cleanup retry interval must be positive")
	}

	empty := initial
	empty.Consumers = nil
	store, err := runtime.NewStore(empty)
	if err != nil {
		return nil, fmt.Errorf("create endpoint runtime: %w", err)
	}
	manager := &Manager{
		store:              store,
		sink:               sink,
		deps:               deps,
		active:             make(map[string]*endpoint),
		pending:            make(map[string]*pendingCleanup),
		pendingPermissions: make(map[string]*pendingPermission),
		stopRetry:          make(chan struct{}),
		retryDone:          make(chan struct{}),
	}
	go manager.retryLoop()
	if _, err := manager.Apply(initial); err != nil {
		closeErr := manager.Close()
		manager.applyMu.Lock()
		for path, pending := range manager.pending {
			closeErr = errors.Join(closeErr, pending.file.parent.close())
			delete(manager.pending, path)
		}
		manager.applyMu.Unlock()
		return nil, errors.Join(err, closeErr)
	}
	return manager, nil
}

// Apply prepares every filesystem and listener change before publishing the
// new runtime snapshot. Preparation failure rolls back staged socket files and
// metadata while leaving the active snapshot and listeners unchanged.
func (manager *Manager) Apply(next config.Config) (ApplyResult, error) {
	manager.applyMu.Lock()
	defer manager.applyMu.Unlock()
	if manager.closed {
		return manager.result(false), ErrClosed
	}

	manager.retryCleanupLocked()
	manager.retryPermissionsLocked()
	if len(manager.pendingPermissions) > 0 {
		return manager.result(false), errors.New("consumer permission transition remains pending")
	}
	prepared, err := manager.store.Prepare(next)
	if err != nil {
		return manager.result(false), err
	}
	plan := prepared.Plan()
	staged, metadata, err := manager.prepare(plan)
	if err != nil {
		rollbackErr := manager.rollback(staged, metadata)
		manager.recordReconciliationFailure(plan)
		return manager.result(false), errors.Join(err, rollbackErr)
	}

	if manager.deps.beforeCommit != nil {
		manager.deps.beforeCommit()
	}
	before := manager.store.Active()
	if err := manager.store.Commit(prepared); err != nil {
		rollbackErr := manager.rollback(staged, metadata)
		return manager.result(false), errors.Join(err, rollbackErr)
	}

	upstreamChanged := before.Upstream() != prepared.Snapshot().Upstream() || before.Timeouts() != prepared.Snapshot().Timeouts()
	for _, update := range plan.Updated() {
		if upstreamChanged || accessGroupChanged(update.Before(), update.After()) {
			manager.active[update.After().Socket()].closeConnections()
		}
	}
	if upstreamChanged {
		for _, consumer := range plan.Retained() {
			manager.active[consumer.Socket()].closeConnections()
		}
	}
	manager.commitMetadataLocked(metadata)

	for _, candidate := range staged {
		active := newEndpoint(manager, candidate.listener, candidate.file, candidate.consumer)
		manager.active[candidate.path] = active
		active.start()
	}

	for _, consumer := range plan.Retired() {
		active := manager.active[consumer.Socket()]
		delete(manager.active, consumer.Socket())
		if active == nil {
			continue
		}
		active.stop()
		manager.cleanupRetiredLocked(consumer.Socket(), active.file)
	}

	manager.recordReconciliation(plan)
	return manager.result(true), nil
}

// RetryCleanup immediately retries every failed post-commit socket removal.
func (manager *Manager) RetryCleanup() Health {
	manager.applyMu.Lock()
	defer manager.applyMu.Unlock()
	if !manager.closed {
		manager.retryCleanupLocked()
		manager.retryPermissionsLocked()
	} else {
		manager.retryCleanupLocked()
	}
	return manager.healthLocked()
}

// Active returns the immutable runtime snapshot active at the instant of the call.
func (manager *Manager) Active() *runtime.Snapshot {
	return manager.store.Active()
}

// Policy resolves the policy active for one socket identity without exposing
// the mutable runtime commit surface outside reconciliation.
func (manager *Manager) Policy(socket string) (runtime.Policy, bool) {
	return manager.store.Policy(socket)
}

// Health returns a current bounded health projection.
func (manager *Manager) Health() Health {
	manager.applyMu.Lock()
	defer manager.applyMu.Unlock()
	return manager.healthLocked()
}

// ConsumerStatuses returns at most limit active endpoint projections in stable
// identifier order. It never exposes the endpoint's filesystem path or policy.
func (manager *Manager) ConsumerStatuses(limit int) ([]ConsumerStatus, bool) {
	manager.applyMu.Lock()
	defer manager.applyMu.Unlock()
	snapshot := manager.store.Active()
	statuses := make([]ConsumerStatus, 0, len(manager.active))
	for path, active := range manager.active {
		consumer, exists := snapshot.Consumer(path)
		if !exists {
			continue
		}
		statuses = append(statuses, ConsumerStatus{
			ID: string(consumerID(path)), Name: consumer.Name(), Listening: !active.isClosing(),
			ActiveConnections: active.connectionCount(),
		})
	}
	slices.SortFunc(statuses, func(left, right ConsumerStatus) int { return strings.Compare(left.ID, right.ID) })
	if limit >= 0 && len(statuses) > limit {
		return statuses[:limit], true
	}
	return statuses, false
}

func (manager *Manager) healthLocked() Health {
	return Health{
		Degraded:           len(manager.pending) > 0 || len(manager.pendingPermissions) > 0 || manager.eventSinkError.Load() || manager.listenerError.Load() || manager.transientListeners.Load() > 0,
		PendingCleanup:     len(manager.pending),
		PendingPermissions: len(manager.pendingPermissions),
		EventSinkError:     manager.eventSinkError.Load(),
		ListenerError:      manager.listenerError.Load(),
	}
}

func (manager *Manager) result(committed bool) ApplyResult {
	health := manager.healthLocked()
	return ApplyResult{Committed: committed, Degraded: health.Degraded, PendingCleanup: health.PendingCleanup, PendingPermissions: health.PendingPermissions}
}

// Close stops accepting, closes every active client pair, and removes only the
// socket files created by this manager. Consumer parent directories remain.
func (manager *Manager) Close() error {
	manager.applyMu.Lock()
	if manager.closed {
		manager.retryCleanupLocked()
		remaining := len(manager.pending)
		manager.applyMu.Unlock()
		if remaining > 0 {
			return errors.New("consumer socket cleanup remains pending")
		}
		return nil
	}
	manager.closed = true
	close(manager.stopRetry)
	manager.applyMu.Unlock()
	<-manager.retryDone

	manager.applyMu.Lock()
	defer manager.applyMu.Unlock()
	var result error
	for path, active := range manager.active {
		active.stop()
		delete(manager.pendingPermissions, path)
		if err := manager.deps.removeSocket(active.file); err != nil {
			manager.pending[path] = &pendingCleanup{file: active.file, consumerID: consumerID(path)}
			result = errors.Join(result, fmt.Errorf("remove consumer socket: %w", err))
		} else {
			result = errors.Join(result, active.file.parent.close())
		}
		delete(manager.active, path)
	}
	manager.retryCleanupLocked()
	if len(manager.pending) > 0 {
		result = errors.Join(result, errors.New("consumer socket cleanup remains pending"))
	}
	return result
}

func accessGroupChanged(before, after runtime.Consumer) bool {
	beforeGroup, beforeHasGroup := before.AccessGroup()
	afterGroup, afterHasGroup := after.AccessGroup()
	return beforeHasGroup != afterHasGroup || beforeHasGroup && beforeGroup != afterGroup
}

func (manager *Manager) recordReconciliation(plan runtime.Plan) {
	seen := make(map[string]struct{})
	record := func(consumer runtime.Consumer) {
		if _, exists := seen[consumer.Socket()]; exists {
			return
		}
		seen[consumer.Socket()] = struct{}{}
		manager.record(events.Event{
			Timestamp:  manager.deps.now(),
			ConsumerID: consumerID(consumer.Socket()),
			Operation:  events.OperationReconcile,
			Outcome:    events.OutcomeSucceeded,
			ErrorCode:  events.ErrorNone,
		})
	}
	for _, consumer := range plan.Added() {
		record(consumer)
	}
	for _, update := range plan.Updated() {
		if _, pending := manager.pendingPermissions[update.After().Socket()]; !pending {
			record(update.After())
		}
	}
	for _, consumer := range plan.Retired() {
		if _, pending := manager.pending[consumer.Socket()]; !pending {
			record(consumer)
		}
	}
}

func (manager *Manager) recordReconciliationFailure(plan runtime.Plan) {
	seen := make(map[string]struct{})
	record := func(consumer runtime.Consumer) {
		if _, exists := seen[consumer.Socket()]; exists {
			return
		}
		seen[consumer.Socket()] = struct{}{}
		manager.record(events.Event{
			Timestamp:  manager.deps.now(),
			ConsumerID: consumerID(consumer.Socket()),
			Operation:  events.OperationReconcile,
			Outcome:    events.OutcomeFailed,
			ErrorCode:  events.ErrorInternal,
		})
	}
	for _, consumer := range plan.Retained() {
		record(consumer)
	}
	for _, update := range plan.Updated() {
		record(update.After())
	}
	for _, consumer := range plan.Added() {
		record(consumer)
	}
}

func (manager *Manager) record(event events.Event) {
	if err := manager.sink.Append(event); err != nil {
		manager.eventSinkError.Store(true)
	}
}

func consumerID(path string) events.ConsumerID {
	digest := sha256.Sum256([]byte(path))
	return events.ConsumerID(hex.EncodeToString(digest[:]))
}
