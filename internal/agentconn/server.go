// ---
// relationships:
//   implements: linux-per-user-agent-proxy
//   uses: operational-events
// ---

package agentconn

import (
	"context"
	"errors"
	"io"

	"github.com/wyrd-company/wyrwood/internal/agentpolicy"
	"github.com/wyrd-company/wyrwood/internal/config"
	"github.com/wyrd-company/wyrwood/internal/events"
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
	return serve(ctx, policies, consumerSocket, upstreamPath, timeouts, downstream, "", nil)
}

// ServeObserved runs one paired downstream connection and emits only closed,
// redacted operational records for its consumer identity.
func ServeObserved(
	ctx context.Context,
	policies agentpolicy.PolicySource,
	consumerSocket string,
	upstreamPath string,
	timeouts config.Timeouts,
	downstream io.ReadWriteCloser,
	consumerID events.ConsumerID,
	record func(events.Event),
) error {
	if record == nil {
		return errors.New("operational event recorder is required")
	}
	return serve(ctx, policies, consumerSocket, upstreamPath, timeouts, downstream, consumerID, record)
}

func serve(
	ctx context.Context,
	policies agentpolicy.PolicySource,
	consumerSocket string,
	upstreamPath string,
	timeouts config.Timeouts,
	downstream io.ReadWriteCloser,
	consumerID events.ConsumerID,
	record func(events.Event),
) error {
	if ctx == nil {
		return errors.New("serve context is required")
	}
	if downstream == nil {
		return errors.New("downstream connection is required")
	}
	defer func() { _ = downstream.Close() }()
	var upstream *Connection
	var err error
	if record == nil {
		upstream, err = New(upstreamPath, timeouts)
	} else {
		upstream, err = newObserved(upstreamPath, timeouts, consumerID, record)
	}
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

	var policyAgent *agentpolicy.Agent
	if record == nil {
		policyAgent, err = agentpolicy.New(policies, consumerSocket, upstream)
	} else {
		policyAgent, err = agentpolicy.NewObserved(policies, consumerSocket, upstream, consumerID, record)
	}
	if err != nil {
		return err
	}
	return agentpolicy.Serve(policyAgent, downstream)
}
