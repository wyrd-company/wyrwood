// ---
// relationships:
//   implements: linux-per-user-agent-proxy
// ---

package runtime

import (
	"maps"
	"slices"
)

// Plan describes deterministic consumer reconciliation without performing I/O.
type Plan struct {
	retained []Consumer
	added    []Consumer
	updated  []ConsumerUpdate
	retired  []Consumer
}

// ConsumerUpdate replaces mutable consumer metadata and policy at one socket.
type ConsumerUpdate struct {
	before Consumer
	after  Consumer
}

func buildPlan(current, next *Snapshot) Plan {
	plan := Plan{}
	for socket, after := range next.consumers {
		before, exists := current.consumers[socket]
		switch {
		case !exists:
			plan.added = append(plan.added, after)
		case consumersEqual(before, after):
			plan.retained = append(plan.retained, after)
		default:
			plan.updated = append(plan.updated, ConsumerUpdate{before: before, after: after})
		}
	}
	for socket, before := range current.consumers {
		if _, exists := next.consumers[socket]; !exists {
			plan.retired = append(plan.retired, before)
		}
	}

	slices.SortFunc(plan.retained, compareConsumerSocket)
	slices.SortFunc(plan.added, compareConsumerSocket)
	slices.SortFunc(plan.updated, func(left, right ConsumerUpdate) int {
		return compareConsumerSocket(left.after, right.after)
	})
	slices.SortFunc(plan.retired, compareConsumerSocket)
	return plan
}

// Retained returns unchanged consumers in socket-path order.
func (plan Plan) Retained() []Consumer {
	return slices.Clone(plan.retained)
}

// Added returns new socket-path security principals in socket-path order.
func (plan Plan) Added() []Consumer {
	return slices.Clone(plan.added)
}

// Updated returns in-place changes in socket-path order.
func (plan Plan) Updated() []ConsumerUpdate {
	return slices.Clone(plan.updated)
}

// Retired returns removed socket-path security principals in socket-path order.
func (plan Plan) Retired() []Consumer {
	return slices.Clone(plan.retired)
}

// Before returns the currently active consumer.
func (update ConsumerUpdate) Before() Consumer {
	return update.before
}

// After returns the candidate replacement at the same socket path.
func (update ConsumerUpdate) After() Consumer {
	return update.after
}

func consumersEqual(left, right Consumer) bool {
	return left.name == right.name &&
		left.socket == right.socket &&
		left.accessGroup == right.accessGroup &&
		left.hasGroup == right.hasGroup &&
		maps.Equal(left.policy.fingerprints, right.policy.fingerprints)
}

func compareConsumerSocket(left, right Consumer) int {
	if left.socket < right.socket {
		return -1
	}
	if left.socket > right.socket {
		return 1
	}
	return 0
}
