// ---
// relationships:
//   implements: container-contract
//   mitigates: recreate-discards-container-writable-layer
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

var (
	errCreateFailed = errors.New("create failed")
	errStartFailed  = errors.New("start failed")
)

func (agent *Agent) recreatingBindingLocked(id string) bool {
	for name := range agent.recreating {
		if state, ok := agent.consumers[name]; ok && state.binding == id {
			return true
		}
	}
	return false
}

// startRecreate recreates one container with its binding's contract when
// the host allows it, and otherwise reports that recreate is not permitted.
func (agent *Agent) startRecreate(ctx context.Context, bound protocol.Binding, container engine.Container) {
	key := events.ContainerKey(string(bound.Key.Kind), bound.Key.Value)
	if !agent.config.AllowRecreate {
		agent.mu.Lock()
		failed := contract.Check(container, bound.Policy.Contract, agent.root.DirectoryPath(container.ShortName()), agent.canAssign)
		agent.reportLocked(protocol.ContractResult{Binding: bound.Binding, Outcome: protocol.OutcomeNonConforming,
			FailedItems: append(failed, protocol.FailedRecreateNotAllowed)})
		agent.mu.Unlock()
		agent.record(events.Event{Operation: events.OperationRecreateBegun, Outcome: events.OutcomeDenied,
			ErrorCode: events.ErrorRecreateNotAllowed, Binding: bound.Binding, ContainerKey: key})
		return
	}
	name := container.ShortName()
	agent.mu.Lock()
	if agent.recreating[name] {
		agent.mu.Unlock()
		return
	}
	agent.recreating[name] = true
	agent.reportLocked(protocol.ContractResult{Binding: bound.Binding, Outcome: protocol.OutcomeRecreating})
	agent.mu.Unlock()
	agent.record(events.Event{Operation: events.OperationRecreateBegun, Outcome: events.OutcomeOK, Binding: bound.Binding, ContainerKey: key})
	go agent.recreate(ctx, bound, container)
}

func (agent *Agent) recreate(ctx context.Context, bound protocol.Binding, container engine.Container) {
	name := container.ShortName()
	key := events.ContainerKey(string(bound.Key.Kind), bound.Key.Value)
	started := time.Now()
	newID, err := agent.performRecreate(ctx, bound, container)
	if errors.Is(err, errCreateFailed) {
		// The preserved create request is retried once; the container is
		// never left absent silently.
		select {
		case <-ctx.Done():
		case <-time.After(recreateRetryDelay):
			newID, err = agent.retryCreate(ctx, name)
		}
	}
	agent.mu.Lock()
	delete(agent.recreating, name)
	delete(agent.pending, name)
	result := protocol.ContractResult{Binding: bound.Binding, Outcome: protocol.OutcomeRecreated, ContainerID: newID}
	code := events.ErrorNone
	if err != nil {
		code = events.ErrorEngineUnavailable
		result = protocol.ContractResult{Binding: bound.Binding, Outcome: protocol.OutcomeRecreateFailed, Reason: recreateReason(err)}
	}
	agent.reportLocked(result)
	agent.mu.Unlock()
	agent.record(events.Event{Operation: events.OperationRecreateFinished, Outcome: outcomeOf(code), ErrorCode: code,
		Binding: bound.Binding, ContainerKey: key, Latency: time.Since(started)})
	_ = agent.fullReconcile(ctx)
}

func recreateReason(err error) protocol.Reason {
	switch {
	case errors.Is(err, errCreateFailed):
		return protocol.ReasonCreateFailed
	case errors.Is(err, errStartFailed):
		return protocol.ReasonStartFailed
	default:
		return protocol.ReasonEngineError
	}
}

func (agent *Agent) performRecreate(ctx context.Context, bound protocol.Binding, observed engine.Container) (string, error) {
	timeout := agent.config.EngineTimeout
	step := func() (context.Context, context.CancelFunc) { return context.WithTimeout(ctx, timeout) }
	operation, cancel := step()
	container, err := agent.engine.Inspect(operation, observed.ID)
	cancel()
	if err != nil {
		return "", err
	}
	operation, cancel = step()
	configuredImage, err := agent.engine.ImageID(operation, container.Config.Image)
	cancel()
	if err != nil {
		configuredImage = ""
	}
	request, err := contract.BuildCreateRequest(container, bound.Policy.Contract, agent.root.DirectoryPath(container.ShortName()), configuredImage)
	if err != nil {
		return "", err
	}
	agent.mu.Lock()
	agent.pending[request.Name] = request
	agent.mu.Unlock()
	stopTimeout := time.Duration(request.Stop) * time.Second
	operation, cancel = context.WithTimeout(ctx, stopTimeout+timeout)
	err = agent.engine.Stop(operation, container.ID, stopTimeout)
	cancel()
	if err != nil {
		return "", err
	}
	operation, cancel = step()
	err = agent.engine.Remove(operation, container.ID)
	cancel()
	if err != nil {
		return "", err
	}
	return agent.createAndStart(ctx, request)
}

func (agent *Agent) retryCreate(ctx context.Context, name string) (string, error) {
	agent.mu.Lock()
	request, ok := agent.pending[name]
	agent.mu.Unlock()
	if !ok {
		return "", errCreateFailed
	}
	return agent.createAndStart(ctx, request)
}

func (agent *Agent) createAndStart(ctx context.Context, request contract.CreateRequest) (string, error) {
	operation, cancel := context.WithTimeout(ctx, agent.config.EngineTimeout)
	id, err := agent.engine.Create(operation, request.Name, request.Body)
	cancel()
	if err != nil {
		return "", errCreateFailed
	}
	if request.Running {
		operation, cancel = context.WithTimeout(ctx, agent.config.EngineTimeout)
		err = agent.engine.Start(operation, id)
		cancel()
		if err != nil {
			return id, errStartFailed
		}
	}
	return id, nil
}
