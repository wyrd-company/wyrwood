// ---
// relationships:
//   implements: linux-per-user-agent-proxy
// ---

package agentconn

import (
	"context"
	"errors"
	"io"

	"github.com/wyrd-company/wyrwood/internal/agentpolicy"
	"github.com/wyrd-company/wyrwood/internal/config"
)

// Serve constructs one unshared upstream pair for exactly one downstream
// connection, then runs the deny-by-default policy endpoint. Upstream failure
// is converted by the endpoint into bounded protocol failure, so the downstream
// connection can make a later request after recovery.
func Serve(
	ctx context.Context,
	policies agentpolicy.PolicySource,
	consumerSocket string,
	upstreamPath string,
	timeouts config.Timeouts,
	downstream io.ReadWriteCloser,
) error {
	if ctx == nil {
		return errors.New("serve context is required")
	}
	if downstream == nil {
		return errors.New("downstream connection is required")
	}
	defer func() { _ = downstream.Close() }()
	upstream, err := New(upstreamPath, timeouts)
	if err != nil {
		return err
	}
	defer func() { _ = upstream.Close() }()
	finished := make(chan struct{})
	defer close(finished)
	go func() {
		select {
		case <-ctx.Done():
			_ = upstream.Close()
			_ = downstream.Close()
		case <-finished:
		}
	}()

	policyAgent, err := agentpolicy.New(policies, consumerSocket, upstream)
	if err != nil {
		return err
	}
	return agentpolicy.Serve(policyAgent, downstream)
}
