//go:build linux

// ---
// relationships:
//   implements: linux-per-user-agent-proxy
// ---

package endpoints

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/wyrd-company/wyrwood/internal/events"
	"github.com/wyrd-company/wyrwood/internal/runtime"
)

func (manager *Manager) prepare(plan runtime.Plan) ([]*stagedSocket, []*metadataChange, error) {
	metadata := make([]*metadataChange, 0, len(plan.Retained())+len(plan.Updated()))
	for _, consumer := range plan.Retained() {
		active := manager.active[consumer.Socket()]
		if active == nil {
			return nil, metadata, errors.New("active listener is absent for retained consumer")
		}
		change, err := manager.deps.prepareActive(consumer, active.file, false)
		if err != nil {
			return nil, metadata, fmt.Errorf("prepare retained consumer permissions: %w", err)
		}
		metadata = append(metadata, change)
	}
	for _, update := range plan.Updated() {
		consumer := update.After()
		active := manager.active[consumer.Socket()]
		if active == nil {
			return nil, metadata, errors.New("active listener is absent for updated consumer")
		}
		change, err := manager.deps.prepareActive(consumer, active.file, accessGroupChanged(update.Before(), update.After()))
		if err != nil {
			return nil, metadata, fmt.Errorf("prepare updated consumer permissions: %w", err)
		}
		metadata = append(metadata, change)
	}

	staged := make([]*stagedSocket, 0, len(plan.Added()))
	for _, consumer := range plan.Added() {
		if _, pending := manager.pending[consumer.Socket()]; pending {
			return staged, metadata, errors.New("prior socket cleanup remains pending for added consumer")
		}
		candidate, err := manager.deps.prepareSocket(consumer)
		if candidate != nil {
			staged = append(staged, candidate)
		}
		if err != nil {
			return staged, metadata, fmt.Errorf("prepare added consumer listener: %w", err)
		}
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
		if err := manager.deps.removeSocket(candidate.file); err != nil {
			manager.pending[candidate.path] = &pendingCleanup{file: candidate.file, consumerID: consumerID(candidate.path)}
			result = errors.Join(result, fmt.Errorf("remove staged socket: %w", err))
		}
		if candidate.parentChange != nil {
			result = errors.Join(result, candidate.parentChange.rollback())
		}
		if _, pending := manager.pending[candidate.path]; !pending {
			result = errors.Join(result, candidate.file.parent.close())
		}
	}
	for index := len(metadata) - 1; index >= 0; index-- {
		result = errors.Join(result, metadata[index].rollback())
	}
	return result
}

func (manager *Manager) cleanupRetiredLocked(path string, file *endpointFile) {
	if err := manager.deps.removeSocket(file); err != nil {
		manager.pending[path] = &pendingCleanup{file: file, consumerID: consumerID(path)}
		manager.record(events.Event{Timestamp: manager.deps.now(), ConsumerID: consumerID(path), Operation: events.OperationReconcile, Outcome: events.OutcomeFailed, ErrorCode: events.ErrorInternal})
		return
	}
	_ = file.parent.close()
}

func (manager *Manager) retryCleanupLocked() {
	for path, pending := range manager.pending {
		if err := manager.deps.removeSocket(pending.file); err != nil {
			continue
		}
		delete(manager.pending, path)
		_ = pending.file.parent.close()
		manager.record(events.Event{Timestamp: manager.deps.now(), ConsumerID: pending.consumerID, Operation: events.OperationReconcile, Outcome: events.OutcomeSucceeded, ErrorCode: events.ErrorNone})
	}
}

func (manager *Manager) commitMetadataLocked(changes []*metadataChange) {
	for _, change := range changes {
		if err := manager.deps.applyPermissions(change); err == nil {
			continue
		}
		path := change.filePath()
		manager.pendingPermissions[path] = &pendingPermission{change: change, consumerID: consumerID(path)}
		manager.record(events.Event{Timestamp: manager.deps.now(), ConsumerID: consumerID(path), Operation: events.OperationReconcile, Outcome: events.OutcomeFailed, ErrorCode: events.ErrorInternal})
	}
}

func (manager *Manager) retryPermissionsLocked() {
	for path, pending := range manager.pendingPermissions {
		if err := manager.deps.applyPermissions(pending.change); err != nil {
			continue
		}
		delete(manager.pendingPermissions, path)
		manager.record(events.Event{Timestamp: manager.deps.now(), ConsumerID: pending.consumerID, Operation: events.OperationReconcile, Outcome: events.OutcomeSucceeded, ErrorCode: events.ErrorNone})
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
				manager.retryPermissionsLocked()
			}
			manager.applyMu.Unlock()
		}
	}
}
