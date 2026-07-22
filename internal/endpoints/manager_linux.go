//go:build linux

// ---
// relationships:
//   implements: linux-per-user-agent-proxy
// ---

// Package endpoints owns Linux AF_UNIX consumer listeners and transactional
// reconciliation of those listeners with immutable runtime configuration.
package endpoints

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wyrd-company/wyrwood/internal/agentconn"
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
	Committed      bool
	Degraded       bool
	PendingCleanup int
}

// Health reports only bounded categorical reconciliation state.
type Health struct {
	Degraded       bool
	PendingCleanup int
	EventSinkError bool
	ListenerError  bool
}

// Manager owns every active consumer listener for one daemon process.
type Manager struct {
	applyMu sync.Mutex
	store   *runtime.Store
	sink    EventSink
	deps    dependencies

	active  map[string]*endpoint
	pending map[string]*pendingCleanup
	closed  bool

	eventSinkError atomic.Bool
	listenerError  atomic.Bool
	stopRetry      chan struct{}
	retryDone      chan struct{}
}

type dependencies struct {
	prepareSocket func(runtime.Consumer) (*stagedSocket, error)
	prepareActive func(runtime.Consumer, fileIdentity) (*metadataChange, error)
	removeSocket  func(string, fileIdentity) error
	now           func() time.Time
	retryInterval time.Duration
	beforeCommit  func()
}

type pendingCleanup struct {
	identity   fileIdentity
	consumerID events.ConsumerID
}

func defaultDependencies() dependencies {
	return dependencies{
		prepareSocket: prepareSocket,
		prepareActive: prepareActiveSocket,
		removeSocket:  removeSocket,
		now:           time.Now,
		retryInterval: defaultCleanupRetryInterval,
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
	if deps.prepareSocket == nil || deps.prepareActive == nil || deps.removeSocket == nil || deps.now == nil {
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
		store:     store,
		sink:      sink,
		deps:      deps,
		active:    make(map[string]*endpoint),
		pending:   make(map[string]*pendingCleanup),
		stopRetry: make(chan struct{}),
		retryDone: make(chan struct{}),
	}
	go manager.retryLoop()
	if _, err := manager.Apply(initial); err != nil {
		_ = manager.Close()
		return nil, err
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

	for _, candidate := range staged {
		active := newEndpoint(manager, candidate.listener, candidate.identity, candidate.consumer)
		manager.active[candidate.path] = active
		active.start()
	}

	if before.Upstream() != prepared.Snapshot().Upstream() || before.Timeouts() != prepared.Snapshot().Timeouts() {
		for _, active := range manager.active {
			active.closeConnections()
		}
	}

	for _, consumer := range plan.Retired() {
		active := manager.active[consumer.Socket()]
		delete(manager.active, consumer.Socket())
		if active == nil {
			continue
		}
		active.stop()
		manager.cleanupRetiredLocked(consumer.Socket(), active.identity)
	}

	manager.recordReconciliation(plan)
	return manager.result(true), nil
}

func (manager *Manager) prepare(plan runtime.Plan) ([]*stagedSocket, []*metadataChange, error) {
	metadata := make([]*metadataChange, 0, len(plan.Retained())+len(plan.Updated()))
	for _, consumer := range plan.Retained() {
		active := manager.active[consumer.Socket()]
		if active == nil {
			return nil, metadata, fmt.Errorf("active listener is absent for retained consumer")
		}
		change, err := manager.deps.prepareActive(consumer, active.identity)
		if err != nil {
			return nil, metadata, fmt.Errorf("prepare retained consumer permissions: %w", err)
		}
		metadata = append(metadata, change)
	}
	for _, update := range plan.Updated() {
		consumer := update.After()
		active := manager.active[consumer.Socket()]
		if active == nil {
			return nil, metadata, fmt.Errorf("active listener is absent for updated consumer")
		}
		change, err := manager.deps.prepareActive(consumer, active.identity)
		if err != nil {
			return nil, metadata, fmt.Errorf("prepare updated consumer permissions: %w", err)
		}
		metadata = append(metadata, change)
	}

	staged := make([]*stagedSocket, 0, len(plan.Added()))
	for _, consumer := range plan.Added() {
		candidate, err := manager.deps.prepareSocket(consumer)
		if candidate != nil {
			staged = append(staged, candidate)
		}
		if err != nil {
			return staged, metadata, fmt.Errorf("prepare added consumer listener: %w", err)
		}
		// Successfully binding this identity proves any older socket at the same
		// path is gone, even if a previous cleanup attempt was pending.
		delete(manager.pending, consumer.Socket())
	}
	return staged, metadata, nil
}

func (manager *Manager) rollback(staged []*stagedSocket, metadata []*metadataChange) error {
	var result error
	for index := len(staged) - 1; index >= 0; index-- {
		candidate := staged[index]
		if err := candidate.listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			result = errors.Join(result, fmt.Errorf("close staged listener: %w", err))
		}
		if err := manager.deps.removeSocket(candidate.path, candidate.identity); err != nil {
			manager.pending[candidate.path] = &pendingCleanup{
				identity:   candidate.identity,
				consumerID: consumerID(candidate.path),
			}
			result = errors.Join(result, fmt.Errorf("remove staged socket: %w", err))
		}
		if candidate.parentChange != nil {
			if err := candidate.parentChange.rollback(); err != nil {
				result = errors.Join(result, fmt.Errorf("restore staged parent metadata: %w", err))
			}
		}
	}
	for index := len(metadata) - 1; index >= 0; index-- {
		if err := metadata[index].rollback(); err != nil {
			result = errors.Join(result, fmt.Errorf("restore active endpoint metadata: %w", err))
		}
	}
	return result
}

func (manager *Manager) cleanupRetiredLocked(path string, identity fileIdentity) {
	if err := manager.deps.removeSocket(path, identity); err != nil {
		manager.pending[path] = &pendingCleanup{identity: identity, consumerID: consumerID(path)}
		manager.record(events.Event{
			Timestamp:  manager.deps.now(),
			ConsumerID: consumerID(path),
			Operation:  events.OperationReconcile,
			Outcome:    events.OutcomeFailed,
			ErrorCode:  events.ErrorInternal,
		})
	}
}

// RetryCleanup immediately retries every failed post-commit socket removal.
func (manager *Manager) RetryCleanup() Health {
	manager.applyMu.Lock()
	defer manager.applyMu.Unlock()
	if !manager.closed {
		manager.retryCleanupLocked()
	}
	return manager.healthLocked()
}

func (manager *Manager) retryCleanupLocked() {
	for path, pending := range manager.pending {
		if err := manager.deps.removeSocket(path, pending.identity); err != nil {
			continue
		}
		delete(manager.pending, path)
		manager.record(events.Event{
			Timestamp:  manager.deps.now(),
			ConsumerID: pending.consumerID,
			Operation:  events.OperationReconcile,
			Outcome:    events.OutcomeSucceeded,
			ErrorCode:  events.ErrorNone,
		})
	}
}

func (manager *Manager) retryLoop() {
	defer close(manager.retryDone)
	ticker := time.NewTicker(manager.deps.retryInterval)
	defer ticker.Stop()
	for {
		select {
		case <-manager.stopRetry:
			return
		case <-ticker.C:
			manager.applyMu.Lock()
			if !manager.closed {
				manager.retryCleanupLocked()
			}
			manager.applyMu.Unlock()
		}
	}
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

func (manager *Manager) healthLocked() Health {
	return Health{
		Degraded:       len(manager.pending) > 0 || manager.eventSinkError.Load() || manager.listenerError.Load(),
		PendingCleanup: len(manager.pending),
		EventSinkError: manager.eventSinkError.Load(),
		ListenerError:  manager.listenerError.Load(),
	}
}

func (manager *Manager) result(committed bool) ApplyResult {
	health := manager.healthLocked()
	return ApplyResult{Committed: committed, Degraded: health.Degraded, PendingCleanup: health.PendingCleanup}
}

// Close stops accepting, closes every active client pair, and removes only the
// socket files created by this manager. Consumer parent directories remain.
func (manager *Manager) Close() error {
	manager.applyMu.Lock()
	if manager.closed {
		manager.applyMu.Unlock()
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
		if err := manager.deps.removeSocket(path, active.identity); err != nil {
			result = errors.Join(result, fmt.Errorf("remove consumer socket: %w", err))
		}
		delete(manager.active, path)
	}
	manager.retryCleanupLocked()
	if len(manager.pending) > 0 {
		result = errors.Join(result, errors.New("consumer socket cleanup remains pending"))
	}
	return result
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
		record(update.After())
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
	return events.ConsumerID("consumer-" + hex.EncodeToString(digest[:16]))
}

type endpoint struct {
	manager  *Manager
	listener *net.UnixListener
	identity fileIdentity
	consumer runtime.Consumer
	ctx      context.Context
	cancel   context.CancelFunc

	mu          sync.Mutex
	connections map[io.Closer]struct{}
	closing     bool
	wg          sync.WaitGroup
}

func newEndpoint(manager *Manager, listener *net.UnixListener, identity fileIdentity, consumer runtime.Consumer) *endpoint {
	ctx, cancel := context.WithCancel(context.Background())
	return &endpoint{
		manager:     manager,
		listener:    listener,
		identity:    identity,
		consumer:    consumer,
		ctx:         ctx,
		cancel:      cancel,
		connections: make(map[io.Closer]struct{}),
	}
}

func (endpoint *endpoint) start() {
	endpoint.wg.Add(1)
	go endpoint.accept()
}

func (endpoint *endpoint) accept() {
	defer endpoint.wg.Done()
	for {
		connection, err := endpoint.listener.AcceptUnix()
		if err != nil {
			endpoint.mu.Lock()
			closing := endpoint.closing
			endpoint.mu.Unlock()
			if !closing {
				endpoint.manager.listenerError.Store(true)
			}
			return
		}
		endpoint.mu.Lock()
		if endpoint.closing {
			endpoint.mu.Unlock()
			_ = connection.Close()
			continue
		}
		endpoint.connections[connection] = struct{}{}
		endpoint.wg.Add(1)
		endpoint.mu.Unlock()
		go endpoint.serve(connection)
	}
}

func (endpoint *endpoint) serve(connection *net.UnixConn) {
	defer endpoint.wg.Done()
	defer func() {
		endpoint.mu.Lock()
		delete(endpoint.connections, connection)
		endpoint.mu.Unlock()
	}()
	endpoint.manager.record(events.Event{
		Timestamp:  endpoint.manager.deps.now(),
		ConsumerID: consumerID(endpoint.consumer.Socket()),
		Operation:  events.OperationConsumerConnect,
		Outcome:    events.OutcomeSucceeded,
		ErrorCode:  events.ErrorNone,
	})
	snapshot := endpoint.manager.store.Active()
	_ = agentconn.Serve(
		endpoint.ctx,
		endpoint.manager.store,
		endpoint.consumer.Socket(),
		snapshot.Upstream(),
		snapshot.Timeouts(),
		connection,
	)
}

func (endpoint *endpoint) closeConnections() {
	endpoint.mu.Lock()
	defer endpoint.mu.Unlock()
	for connection := range endpoint.connections {
		_ = connection.Close()
	}
}

func (endpoint *endpoint) stop() {
	endpoint.mu.Lock()
	if endpoint.closing {
		endpoint.mu.Unlock()
		endpoint.wg.Wait()
		return
	}
	endpoint.closing = true
	endpoint.cancel()
	_ = endpoint.listener.Close()
	for connection := range endpoint.connections {
		_ = connection.Close()
	}
	endpoint.mu.Unlock()
	endpoint.wg.Wait()
}
