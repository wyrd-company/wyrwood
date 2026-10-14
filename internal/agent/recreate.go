// ---
// relationships:
//   implements: container-contract
//   mitigates: recreate-discards-container-writable-layer
// ---

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
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

// recreateJournal is written before a recreate stops its container. A
// successful recreate removes it. A failed recreate, or one an agent exit
// interrupted, makes it terminal by recording the outcome and reason, and
// it is removed once that result is sent to the controller, so the report
// survives restarts. It names the binding and container only; the create
// request, which carries the container's environment, stays in memory.
type recreateJournal struct {
	Version int              `json:"version"`
	Binding string           `json:"binding"`
	Key     protocol.Key     `json:"key"`
	Outcome protocol.Outcome `json:"outcome,omitempty"`
	Reason  protocol.Reason  `json:"reason,omitempty"`
}

func (journal recreateJournal) result() protocol.ContractResult {
	return protocol.ContractResult{Binding: journal.Binding, Outcome: journal.Outcome, Reason: journal.Reason}
}

func (agent *Agent) writeJournal(name string, journal recreateJournal) error {
	data, err := json.Marshal(journal)
	if err != nil {
		return err
	}
	return writeOwnerOnly(agent.paths.RecreateJournal(name), data, false)
}

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
	result := protocol.ContractResult{Binding: bound.Binding, Outcome: protocol.OutcomeRecreated, ContainerID: newID}
	code := events.ErrorNone
	if err != nil {
		code = events.ErrorEngineUnavailable
		journal := recreateJournal{Version: 1, Binding: bound.Binding, Key: bound.Key,
			Outcome: protocol.OutcomeRecreateFailed, Reason: recreateReason(err)}
		result = journal.result()
		if journalErr := agent.writeJournal(name, journal); journalErr != nil {
			agent.logf("recreate journal not written")
		}
	} else if removeErr := os.Remove(agent.paths.RecreateJournal(name)); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
		agent.logf("recreate journal not removed")
	}
	agent.mu.Lock()
	delete(agent.recreating, name)
	delete(agent.pending, name)
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
	if err := agent.writeJournal(request.Name, recreateJournal{Version: 1, Binding: bound.Binding, Key: bound.Key}); err != nil {
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
		// The original container still exists; leave it as it was found.
		if request.Running {
			operation, cancel = step()
			_ = agent.engine.Start(operation, container.ID)
			cancel()
		}
		return "", err
	}
	return agent.createAndStart(ctx, request)
}

// reportInterruptedRecreatesLocked reports each recreate a previous agent
// process began and did not finish, using observed, the full engine view,
// and reports again each failure not yet sent to the controller. For an
// unfinished journal, a container with the journaled name means the
// recreate got that far and reconcile reports its conformance; an absent
// one is a failed recreate, recorded in the journal until it is sent.
func (agent *Agent) reportInterruptedRecreatesLocked(observed map[string]engine.Container) {
	entries, err := os.ReadDir(agent.paths.RecreateJournals())
	if err != nil {
		return
	}
	present := map[string]bool{}
	for _, container := range observed {
		present[container.ShortName()] = true
	}
	for _, entry := range entries {
		name, ok := strings.CutSuffix(entry.Name(), ".json")
		if !ok || entry.IsDir() || agent.recreating[name] {
			continue
		}
		path := agent.paths.RecreateJournal(name)
		data, err := os.ReadFile(path)
		var journal recreateJournal
		if err != nil || json.Unmarshal(data, &journal) != nil || journal.Version != 1 ||
			(journal.Outcome == "" && present[name]) {
			if err := os.Remove(path); err != nil {
				agent.logf("recreate journal not removed")
			}
			continue
		}
		if journal.Outcome == "" {
			journal.Outcome, journal.Reason = protocol.OutcomeRecreateFailed, protocol.ReasonCreateFailed
			if err := agent.writeJournal(name, journal); err != nil {
				agent.logf("recreate journal not written")
			}
			agent.record(events.Event{Operation: events.OperationRecreateFinished, Outcome: events.OutcomeFailed,
				ErrorCode: events.ErrorEngineUnavailable, Binding: journal.Binding,
				ContainerKey: events.ContainerKey(string(journal.Key.Kind), journal.Key.Value)})
		}
		agent.reportLocked(journal.result())
	}
}

// resultSent removes the terminal journal a sent contract result reports.
func (agent *Agent) resultSent(message protocol.Message) {
	result, ok := message.(protocol.ContractResult)
	if !ok || result.Outcome != protocol.OutcomeRecreateFailed {
		return
	}
	entries, err := os.ReadDir(agent.paths.RecreateJournals())
	if err != nil {
		return
	}
	for _, entry := range entries {
		name, ok := strings.CutSuffix(entry.Name(), ".json")
		if !ok || entry.IsDir() {
			continue
		}
		path := agent.paths.RecreateJournal(name)
		data, err := os.ReadFile(path)
		var journal recreateJournal
		if err != nil || json.Unmarshal(data, &journal) != nil || !sameResult(journal.result(), result) || journal.Binding != result.Binding {
			continue
		}
		if err := os.Remove(path); err != nil {
			agent.logf("recreate journal not removed")
		}
	}
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
