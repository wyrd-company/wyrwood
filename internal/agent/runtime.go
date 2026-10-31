// ---
// relationships:
//   implements: agent
//   uses: engine-proxy
// ---

package agent

import (
	"context"
	"errors"
	"io"
	"log"
	"net"

	"github.com/wyrd-company/wyrwood/internal/binding"
	"github.com/wyrd-company/wyrwood/internal/config"
	"github.com/wyrd-company/wyrwood/internal/engine"
	"github.com/wyrd-company/wyrwood/internal/engineproxy"
	"github.com/wyrd-company/wyrwood/internal/sshagent"
	"github.com/wyrd-company/wyrwood/internal/vaultproxy"
)

// ErrConfiguration marks invalid or unreadable agent configuration.
var ErrConfiguration = errors.New("agent configuration unavailable")

// RunDaemon runs the shared host agent runtime for standalone and controller
// commands, retaining the same Engine permission boundary and local interfaces.
func RunDaemon(ctx context.Context, paths Paths, version string, output io.Writer) error {
	configuration, err := config.LoadAgent(paths.Config)
	if err != nil {
		return ErrConfiguration
	}
	if err := engineproxy.CheckAgentAccess(configuration.EngineSocket); err != nil {
		return err
	}
	Version = version
	// Library diagnostics, such as ssh-agent request failures, are already
	// recorded as categorical events and are not repeated to the journal.
	log.SetOutput(io.Discard)
	instance, err := New(Options{
		Config: configuration, Paths: paths, Engine: engine.NewClient(configuration.EngineProxySocket), Log: output,
		Endpoints: endpoints{vault: vaultproxy.New(configuration.OpenBaoTimeout), ssh: sshagent.New(configuration.SignTimeout)},
	})
	if err != nil {
		return err
	}
	return instance.Run(ctx)
}

// endpoints serves both consumer sockets.
type endpoints struct {
	vault *vaultproxy.Proxy
	ssh   *sshagent.Endpoint
}

func (set endpoints) ServeVault(listener net.Listener, lookup binding.Lookup, record binding.Recorder) {
	set.vault.Serve(listener, lookup, record)
}

func (set endpoints) ServeSSHAgent(listener net.Listener, lookup binding.Lookup, record binding.Recorder) {
	set.ssh.Serve(listener, lookup, record)
}
