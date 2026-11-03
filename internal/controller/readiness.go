// ---
// relationships:
//   implements:
//     - controller
//     - agent-controller-protocol
// ---

package controller

import (
	"context"
	"errors"
	"slices"
	"sort"
	"time"

	"github.com/wyrd-company/wyrwood/internal/controller/store"
	"github.com/wyrd-company/wyrwood/internal/protocol"
)

// Readiness says whether a binding's consumers can use their sockets now.
type Readiness string

const (
	// ReadinessReady means every matched container has its directory, both
	// sockets, and a valid token, and conforms. It holds for any container
	// state, so that a created container can be started.
	ReadinessReady Readiness = "ready"
	// ReadinessWaiting means a step is still to come, or may recover alone.
	ReadinessWaiting Readiness = "waiting"
	// ReadinessFailed means the setup is wrong and needs a change.
	ReadinessFailed Readiness = "failed"
	// ReadinessUnknown means no agent session can answer.
	ReadinessUnknown Readiness = "unknown"
)

// NotReadyReason names one thing that keeps a binding from being ready.
type NotReadyReason string

const (
	ReasonAgentDisconnected NotReadyReason = "agent-disconnected"
	ReasonAgentReport       NotReadyReason = "agent-report"
	ReasonNoContainer       NotReadyReason = "container"
	ReasonConsumerDirectory NotReadyReason = "consumer-directory"
	ReasonAccessGroup       NotReadyReason = "access-group"
	ReasonSockets           NotReadyReason = "sockets"
	ReasonToken             NotReadyReason = "token"
	ReasonConformance       NotReadyReason = "conformance"
)

// BindingStatus is the machine-readable answer to whether a binding is ready.
// It holds no token or secret. Only a live agent session supplies its
// directory, socket, token, and conformance fields, so that a removed
// container cannot read as conforming.
type BindingStatus struct {
	Binding        string                    `json:"binding"`
	Agent          string                    `json:"agent"`
	Key            protocol.Key              `json:"key"`
	AgentConnected bool                      `json:"agent-connected"`
	LastReport     time.Time                 `json:"last-report,omitzero"`
	Readiness      Readiness                 `json:"readiness"`
	Reasons        []NotReadyReason          `json:"reasons,omitempty"`
	Containers     []BindingContainer        `json:"containers"`
	Consumers      []protocol.ConsumerStatus `json:"consumers"`
	Token          protocol.TokenState       `json:"token,omitempty"`
	Outcome        protocol.Outcome          `json:"outcome,omitempty"`
	FailedItems    []protocol.FailedItem     `json:"failed-items,omitempty"`
	Reason         protocol.Reason           `json:"reason,omitempty"`
	LastError      protocol.CredentialError  `json:"last-error,omitempty"`
}

// BindingContainer is one reported container a binding governs.
type BindingContainer struct {
	ID    string         `json:"id"`
	Name  string         `json:"name"`
	State protocol.State `json:"state"`
}

// recordStatus keeps a status for the agent's own binding. A failed lookup
// keeps it too: reads go through the stored binding, and the agent sends a
// status only when it changes.
func (session *agentSession) recordStatus(ctx context.Context, status protocol.BindingStatus) {
	binding, err := session.controller.store.Binding(ctx, status.Binding)
	if errors.Is(err, store.ErrNotFound) || (err == nil && binding.Agent != session.agent) {
		return
	}
	session.mu.Lock()
	session.statuses[status.Binding] = status
	session.mu.Unlock()
}

func (session *agentSession) status(binding string) (protocol.BindingStatus, bool) {
	session.mu.Lock()
	defer session.mu.Unlock()
	status, ok := session.statuses[binding]
	return status, ok
}

// BindingStatus returns one binding's readiness.
func (controller *Controller) BindingStatus(ctx context.Context, id string) (BindingStatus, error) {
	binding, err := controller.store.Binding(ctx, id)
	if err != nil {
		return BindingStatus{}, err
	}
	containers, reported, err := controller.store.Inventory(ctx, binding.Agent)
	if err != nil {
		return BindingStatus{}, err
	}
	bindings, err := controller.store.Bindings(ctx, binding.Agent)
	if err != nil {
		return BindingStatus{}, err
	}
	return controller.bindingStatus(binding, governedBy(containers, bindings)[binding.ID], reported), nil
}

// BindingStatuses returns the readiness of every binding of one agent.
func (controller *Controller) BindingStatuses(ctx context.Context, agent string) ([]BindingStatus, error) {
	bindings, err := controller.store.Bindings(ctx, agent)
	if err != nil {
		return nil, err
	}
	containers, reported, err := controller.store.Inventory(ctx, agent)
	if err != nil {
		return nil, err
	}
	governed := governedBy(containers, bindings)
	statuses := make([]BindingStatus, 0, len(bindings))
	for _, binding := range bindings {
		statuses = append(statuses, controller.bindingStatus(binding, governed[binding.ID], reported))
	}
	return statuses, nil
}

func governedBy(containers []protocol.Container, bindings []store.Binding) map[string][]BindingContainer {
	governed := map[string][]BindingContainer{}
	for _, container := range containers {
		if binding, ok := ContainerBinding(container, bindings); ok {
			governed[binding.ID] = append(governed[binding.ID], BindingContainer{ID: container.ID, Name: container.Name, State: container.State})
		}
	}
	return governed
}

func (controller *Controller) bindingStatus(binding store.Binding, containers []BindingContainer, reported time.Time) BindingStatus {
	sort.Slice(containers, func(left, right int) bool { return containers[left].ID < containers[right].ID })
	result := BindingStatus{Binding: binding.ID, Agent: binding.Agent, Key: binding.Key, LastReport: reported,
		Containers: containers, Consumers: []protocol.ConsumerStatus{}}
	if result.Containers == nil {
		result.Containers = []BindingContainer{}
	}
	session := controller.hub.session(binding.Agent)
	if session == nil {
		result.Readiness, result.Reasons = ReadinessUnknown, []NotReadyReason{ReasonAgentDisconnected}
		return result
	}
	result.AgentConnected = true
	report, ok := session.status(binding.ID)
	if !ok || report.Assignment != binding.Assignment() {
		// The agent carries only a name binding before its container exists.
		result.Readiness = ReadinessWaiting
		if len(containers) == 0 && binding.Key.Kind != protocol.KeyName {
			result.Reasons = []NotReadyReason{ReasonNoContainer}
		} else {
			result.Reasons = []NotReadyReason{ReasonAgentReport}
		}
		return result
	}
	result.Token, result.LastError = report.Token, report.LastError
	result.Outcome, result.FailedItems, result.Reason = report.Outcome, report.FailedItems, report.Reason
	result.Consumers = append(result.Consumers, report.Consumers...)
	waiting, failed := judge(containers, report)
	result.Reasons = append(failed, waiting...)
	switch {
	case len(failed) > 0:
		result.Readiness = ReadinessFailed
	case len(waiting) > 0:
		result.Readiness = ReadinessWaiting
	default:
		result.Readiness = ReadinessReady
	}
	return result
}

// judge lists what keeps the binding from being ready, split into what may
// still come and what needs a change.
func judge(containers []BindingContainer, report protocol.BindingStatus) (waiting, failed []NotReadyReason) {
	note := func(list *[]NotReadyReason, reason NotReadyReason) {
		if !slices.Contains(*list, reason) {
			*list = append(*list, reason)
		}
	}
	for _, consumer := range report.Consumers {
		switch consumer.Failed {
		case "":
		case protocol.FailedAccessGroup:
			note(&failed, ReasonAccessGroup)
		default:
			note(&failed, ReasonConsumerDirectory)
		}
	}
	if len(containers) == 0 {
		note(&waiting, ReasonNoContainer)
		return waiting, failed
	}
	for _, container := range containers {
		index := slices.IndexFunc(report.Consumers, func(consumer protocol.ConsumerStatus) bool { return consumer.ContainerID == container.ID })
		switch {
		case index < 0:
			note(&waiting, ReasonAgentReport)
		case report.Consumers[index].Failed == "" && !allSockets(report.Consumers[index].Sockets):
			note(&waiting, ReasonSockets)
		}
	}
	if report.Token != protocol.TokenValid {
		note(&waiting, ReasonToken)
	}
	switch report.Outcome {
	case protocol.OutcomeConforming, protocol.OutcomeRecreated:
	case protocol.OutcomeNonConforming, protocol.OutcomeRecreateFailed:
		note(&failed, ReasonConformance)
	default:
		note(&waiting, ReasonConformance)
	}
	return waiting, failed
}

func allSockets(sockets []protocol.Socket) bool {
	for _, socket := range protocol.Sockets {
		if !slices.Contains(sockets, socket) {
			return false
		}
	}
	return true
}
