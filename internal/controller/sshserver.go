// ---
// relationships:
//   implements:
//     - controller
//     - agent-controller-protocol
//   uses: enroll-agents-with-host-generated-keys
// ---

package controller

import (
	"context"
	"regexp"
	"strings"
	"time"

	"charm.land/ssh"
	"charm.land/wish/v2"
	gossh "golang.org/x/crypto/ssh"

	"github.com/wyrd-company/wyrwood/internal/controller/store"
	"github.com/wyrd-company/wyrwood/internal/protocol"
)

var hostnamePattern = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,62})(\.[A-Za-z0-9]([A-Za-z0-9-]{0,62}))*$`)

// ValidAgentName reports whether name is an acceptable presented hostname.
func ValidAgentName(name string) bool {
	return len(name) <= 253 && hostnamePattern.MatchString(name)
}

type authenticatedAgent struct {
	fingerprint string
	name        string
}

type agentContextKey struct{}

func (controller *Controller) newSSHServer(signer gossh.Signer) (*ssh.Server, error) {
	server, err := wish.NewServer(
		wish.WithAddress(controller.config.SSHListen),
		wish.WithVersion("SSH-2.0-Wyrwood"),
		wish.WithPublicKeyAuth(controller.authenticate),
		wish.WithSubsystem(protocol.SubsystemName, controller.serveSubsystem),
		wish.WithIdleTimeout(10*time.Minute),
		func(server *ssh.Server) error {
			server.AddHostKey(signer)
			// Shell, exec, and every other session request is refused.
			server.Handler = func(session ssh.Session) { _ = session.Exit(1) }
			return nil
		},
	)
	if err != nil {
		return nil, err
	}
	return server, nil
}

// authenticate accepts only approved keys presented with the approved name.
// An unknown key is recorded as pending; pending, rejected, and unknown keys
// all receive the same authentication failure.
func (controller *Controller) authenticate(ctx ssh.Context, key ssh.PublicKey) bool {
	name := ctx.User()
	if !ValidAgentName(name) {
		return false
	}
	fingerprint := gossh.FingerprintSHA256(key)
	lookup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	agent, err := controller.store.Agent(lookup, fingerprint)
	if err == store.ErrNotFound {
		count, countErr := controller.store.PendingCount(lookup)
		if countErr != nil || count >= maximumPendingKeys {
			return false
		}
		authorized := strings.TrimSpace(string(gossh.MarshalAuthorizedKey(key)))
		if _, err := controller.store.RecordKey(lookup, fingerprint, name, authorized, controller.now()); err != nil {
			controller.logf("pending key not recorded")
		}
		return false
	}
	if err != nil || agent.State != store.AgentApproved || agent.Name != name {
		return false
	}
	ctx.SetValue(agentContextKey{}, authenticatedAgent{fingerprint: fingerprint, name: name})
	return true
}

func (controller *Controller) serveSubsystem(session ssh.Session) {
	identity, ok := session.Context().Value(agentContextKey{}).(authenticatedAgent)
	if !ok {
		_ = session.Exit(1)
		return
	}
	controller.hub.serve(session.Context(), identity, session)
	_ = session.Exit(0)
}
