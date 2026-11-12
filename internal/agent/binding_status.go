// ---
// relationships:
//   implements:
//     - agent
//     - agent-controller-protocol
// ---

package agent

import (
	"reflect"
	"sort"

	"github.com/wyrd-company/wyrwood/internal/consumer"
	"github.com/wyrd-company/wyrwood/internal/engine"
	"github.com/wyrd-company/wyrwood/internal/protocol"
)

// wakeStatus asks the session's reporter to compare binding statuses. It never
// blocks and takes no lock; a pending wake already covers this change.
func (agent *Agent) wakeStatus() {
	select {
	case agent.statusWake <- struct{}{}:
	default:
	}
}

// reportBindingStatuses sends each binding's status once at the start of a
// session and again when it changes, until the session ends.
func (agent *Agent) reportBindingStatuses(session *controllerSession) {
	sent := map[string]protocol.BindingStatus{}
	for {
		current := map[string]bool{}
		for _, status := range agent.bindingStatuses() {
			current[status.Binding] = true
			if previous, ok := sent[status.Binding]; !ok || !reflect.DeepEqual(previous, status) {
				sent[status.Binding] = status
				session.send(status)
			}
		}
		for id := range sent {
			if !current[id] {
				delete(sent, id)
			}
		}
		select {
		case <-session.done:
			return
		case <-agent.statusWake:
		}
	}
}

// bindingStatuses reports every binding in the policy set from current state:
// the containers it governs now, and no result for a binding that governs none.
func (agent *Agent) bindingStatuses() []protocol.BindingStatus {
	// A policy set replaces an assignment and invalidates its token under this
	// lock, so these reads cannot pair an old token with a new assignment.
	agent.mu.Lock()
	defer agent.mu.Unlock()
	holding := agent.creds.holding()
	failures := agent.creds.lastFailures()
	governed := map[string][]engine.Container{}
	for _, container := range agent.containers {
		if bound, ok := agent.governingLocked(container); ok {
			governed[bound.Binding] = append(governed[bound.Binding], container)
		}
	}
	statuses := make([]protocol.BindingStatus, 0, len(agent.set.Bindings))
	for _, bound := range agent.set.Bindings {
		containers := governed[bound.Binding]
		sort.Slice(containers, func(left, right int) bool { return containers[left].ID < containers[right].ID })
		status := protocol.BindingStatus{Binding: bound.Binding, Assignment: bound.Assignment, Token: tokenState(holding, bound.Binding),
			Consumers: []protocol.ConsumerStatus{}, LastError: failures[bound.Binding]}
		for _, container := range containers {
			status.Consumers = append(status.Consumers, agent.consumerStatusLocked(bound, directoryName(bound, container), container.ID))
		}
		if name := bound.PreparedDirectory(); len(containers) == 0 && name != "" && consumer.ValidName(name) {
			status.Consumers = append(status.Consumers, agent.consumerStatusLocked(bound, name, ""))
		}
		if len(containers) > 0 || agent.recreatingBindingLocked(bound.Binding) {
			if result, ok := agent.results[bound.Binding]; ok {
				status.Outcome, status.FailedItems, status.Reason = result.Outcome, result.FailedItems, result.Reason
			}
		}
		statuses = append(statuses, status)
	}
	return statuses
}

func tokenState(holding map[string]bool, id string) protocol.TokenState {
	valid, held := holding[id]
	switch {
	case !held:
		return protocol.TokenNone
	case valid:
		return protocol.TokenValid
	default:
		return protocol.TokenExpired
	}
}

// consumerStatusLocked reports the directory for one container name. A name
// another binding's container holds has no status for this binding beyond its
// path: the other binding governs that directory.
func (agent *Agent) consumerStatusLocked(bound protocol.Binding, name, containerID string) protocol.ConsumerStatus {
	status := protocol.ConsumerStatus{ContainerID: containerID}
	if !consumer.ValidName(name) {
		status.Failed = protocol.FailedConsumerDirectory
		return status
	}
	status.Directory = agent.root.DirectoryPath(name)
	wanted := bound.Policy.Contract.AccessGroup
	state, ok := agent.consumers[name]
	switch {
	case !ok:
		status.Failed = protocol.FailedConsumerDirectory
		if wanted != nil && !agent.canAssign(*wanted) {
			status.Failed = protocol.FailedAccessGroup
		}
	case state.binding != bound.Binding:
	default:
		status.AccessGroup = state.group
		status.Sockets = append(status.Sockets, state.sockets...)
		if len(state.sockets) != len(protocol.Sockets) {
			status.Failed = protocol.FailedConsumerDirectory
		}
		if !sameGroup(state.group, wanted) {
			status.Failed = protocol.FailedAccessGroup
		}
	}
	return status
}
