// ---
// relationships:
//   implements:
//     - controller
//     - composable-policy-bindings
// ---

package controller

import (
	"context"
	"errors"
	"slices"

	"github.com/wyrd-company/wyrwood/internal/events"
	"github.com/wyrd-company/wyrwood/internal/policy"
	"github.com/wyrd-company/wyrwood/internal/protocol"
)

// BindingTarget names what a binding binds: a container key on an agent and,
// for a key that is not name, the consumer directory name the operator gives.
type BindingTarget struct {
	Agent     string
	Key       protocol.Key
	Directory string
	// waits lets a key that is not name, with no directory, bind a container
	// that no agent reports. It is set only by the callers that carry no
	// directory input, so that they keep binding as they always did.
	waits bool
}

var (
	// ErrDirectoryRequired refuses a binding whose key is not name, for a
	// container its agent does not report, without a directory name.
	ErrDirectoryRequired = errors.New("the agent reports no container with this key; give the directory name its container will mount")
	// ErrDirectoryInUse refuses a directory name that another binding on the
	// agent already names.
	ErrDirectoryInUse = errors.New("another binding on this agent already uses this directory name")
)

func directoryError(cause error) error {
	return &OperationError{Message: cause.Error(), Code: events.ErrorPolicyDenied, Part: policy.PartKey, Cause: cause}
}

// validateDirectory applies the directory name rule and keeps one agent's
// directories distinct.
func (controller *Controller) validateDirectory(ctx context.Context, target BindingTarget) error {
	if target.Directory != "" {
		if target.Key.Kind == protocol.KeyName {
			return directoryError(protocol.ErrDirectoryNameForName)
		}
		if err := protocol.ValidateDirectoryName(target.Directory); err != nil {
			return directoryError(err)
		}
	}
	name := protocol.Binding{Key: target.Key, Directory: target.Directory}.PreparedDirectory()
	if name != "" {
		bindings, err := controller.store.Bindings(ctx, target.Agent)
		if err != nil {
			return operationError(events.ErrorInternal, "the agent's bindings could not be read")
		}
		for _, other := range bindings {
			// Two name bindings with one value are one key, which the store refuses.
			if other.PreparedDirectory() == name && (target.Directory != "" || other.Directory != "") {
				return directoryError(ErrDirectoryInUse)
			}
		}
	}
	return nil
}

// requireDirectory asks for a directory name where nothing else names one: a
// key that is not name, for a container its agent does not report. It reads
// the inventory last, so that a refusal of the request itself comes first.
func (controller *Controller) requireDirectory(ctx context.Context, target BindingTarget) error {
	if target.waits || target.Key.Kind == protocol.KeyName || target.Directory != "" {
		return nil
	}
	containers, _, err := controller.store.Inventory(ctx, target.Agent)
	if err != nil {
		return operationError(events.ErrorInternal, "the agent's containers could not be read")
	}
	for _, container := range containers {
		if slices.Contains(container.Keys, target.Key) {
			return nil
		}
	}
	return directoryError(ErrDirectoryRequired)
}
