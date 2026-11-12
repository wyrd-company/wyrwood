// ---
// relationships:
//   implements: agent
//   uses: engine-proxy
// ---

package agent

import (
	"context"
	"errors"
	"time"

	"github.com/wyrd-company/wyrwood/internal/contract"
	"github.com/wyrd-company/wyrwood/internal/engine"
	"github.com/wyrd-company/wyrwood/internal/events"
	"github.com/wyrd-company/wyrwood/internal/protocol"
)

// startFailedMountsLocked starts each bound container whose start failed on
// its consumer directory, once its sockets are ready. /run is empty at boot and
// Docker starts containers before the agent runs, so this happens on every
// reboot. A container that fails again is tried once per reconcile interval.
func (agent *Agent) startFailedMountsLocked(ctx context.Context) {
	for id := range agent.startAttempts {
		container, ok := agent.containers[id]
		if !ok || !contract.StartFailedOnMount(container, agent.containerDirectoryLocked(container)) {
			delete(agent.startAttempts, id)
		}
	}
	for id, container := range agent.containers {
		if !contract.StartFailedOnMount(container, agent.containerDirectoryLocked(container)) {
			continue
		}
		bound, ok := agent.governingLocked(container)
		if !ok || !agent.readyToStartLocked(container) {
			continue
		}
		if last, tried := agent.startAttempts[id]; tried && time.Since(last) < reconcileInterval {
			continue
		}
		if agent.stopping || ctx.Err() != nil {
			return
		}
		agent.startAttempts[id] = time.Now()
		agent.engineWorkers.Add(1)
		go func() {
			defer agent.engineWorkers.Done()
			agent.startAfterFailedMount(ctx, bound, id)
		}()
	}
}

// readyToStartLocked reports whether a binding governs container, no recreate
// holds it, and its directory and both sockets are ready.
func (agent *Agent) readyToStartLocked(container engine.Container) bool {
	bound, ok := agent.governingLocked(container)
	if !ok || agent.recreating[container.ShortName()] {
		return false
	}
	state := agent.consumers[directoryName(bound, container)]
	return state != nil && state.binding == bound.Binding && len(state.listeners) == 2 &&
		sameGroup(state.group, bound.Policy.Contract.AccessGroup)
}

// startAfterFailedMount starts one container and records the outcome.
func (agent *Agent) startAfterFailedMount(ctx context.Context, bound protocol.Binding, id string) {
	started := time.Now()
	operation, cancel := context.WithTimeout(ctx, agent.config.EngineTimeout)
	defer cancel()
	attempted, err := agent.startIfStillFailed(operation, id)
	if !attempted {
		return
	}
	code := events.ErrorNone
	if err != nil {
		code = events.ErrorEngineUnavailable
		agent.logf("container start after a failed mount did not succeed")
	}
	agent.record(events.Event{Operation: events.OperationContainerStarted, Outcome: outcomeOf(code), ErrorCode: code, Binding: bound.Binding,
		ContainerKey: events.ContainerKey(string(bound.Key.Kind), bound.Key.Value), Latency: time.Since(started)})
}

// startIfStillFailed decides again on a fresh inspect, so that a container
// someone started or changed, or a binding withdrawn, during the inspect is
// respected. A withdrawal after this decision is the same as one just after
// the start: the sockets go away from a running container.
func (agent *Agent) startIfStillFailed(ctx context.Context, id string) (bool, error) {
	container, err := agent.engine.Inspect(ctx, id)
	if errors.Is(err, engine.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return true, err
	}
	agent.mu.Lock()
	ready := agent.readyToStartLocked(container)
	directory := agent.containerDirectoryLocked(container)
	agent.mu.Unlock()
	if !ready || !contract.StartFailedOnMount(container, directory) {
		return false, nil
	}
	return true, agent.engine.Start(ctx, id)
}
