// ---
// relationships:
//   implements:
//     - agent
//     - vault-socket-proxy
//     - ssh-agent-endpoint
// ---

// Package binding is the boundary between the agent and the endpoints it
// serves: each endpoint request looks up the container's current binding
// and token through a Lookup so policy changes apply on the next request.
package binding

import (
	"net"

	"github.com/openbao/openbao/api/v2"

	"github.com/wyrd-company/wyrwood/internal/events"
	"github.com/wyrd-company/wyrwood/internal/openbao"
	"github.com/wyrd-company/wyrwood/internal/policy"
	"github.com/wyrd-company/wyrwood/internal/protocol"
)

// View is one consumer's current binding as an endpoint sees it.
type View struct {
	ID           string
	ContainerKey string
	Policy       policy.Effective
	OpenBao      protocol.OpenBao
	Mounts       Mounts
	Client       *api.Client
	Token        openbao.Token
	HasToken     bool
}

// Mounts names the OpenBao mounts the ssh-agent endpoint uses.
type Mounts struct {
	Transit string
	SSH     string
}

// Lookup returns the consumer's current binding, or false when unbound.
type Lookup func() (View, bool)

// Recorder records one operational event.
type Recorder func(events.Event)

// Endpoints serves the two consumer sockets. Each Serve call returns when the
// listener is closed.
type Endpoints interface {
	ServeVault(listener net.Listener, lookup Lookup, record Recorder)
	ServeSSHAgent(listener net.Listener, lookup Lookup, record Recorder)
}
