// ---
// relationships:
//   implements: linux-per-user-agent-proxy
// ---

// Package agentconn owns one fixed-path upstream SSH-agent connection for each
// downstream connection and reconstructs its connection-scoped session state.
package agentconn

import (
	"context"
	"errors"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/wyrd-company/wyrwood/internal/config"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

const sessionBindExtension = "session-bind@openssh.com"

var (
	// ErrClosed means the paired connection has ended with its downstream owner.
	ErrClosed = errors.New("paired upstream connection is closed")
	// ErrConnect categorizes a bounded failure to connect at the configured path.
	ErrConnect = errors.New("upstream connect failed")
	// ErrReplay categorizes a failure to restore accepted session bindings.
	ErrReplay = errors.New("upstream session binding replay failed")
	// ErrList categorizes an upstream identity-list failure.
	ErrList = errors.New("upstream identity list failed")
	// ErrSign categorizes an upstream signing failure.
	ErrSign = errors.New("upstream signing failed")
	// ErrExtension categorizes an upstream session-binding failure.
	ErrExtension = errors.New("upstream session binding failed")
	// ErrOperationDenied means the paired adapter does not expose an operation.
	ErrOperationDenied = errors.New("upstream operation is not exposed")
	// ErrClose categorizes a failure to close the owned upstream stream.
	ErrClose = errors.New("upstream close failed")
)

// Connection owns the one upstream stream paired with a downstream client.
// It is safe for concurrent use, although the downstream protocol normally
// serializes requests. It never logs or embeds paths, payloads, signatures,
// destinations, comments, public keys, or upstream errors in returned errors.
type Connection struct {
	operationMu sync.Mutex
	stateMu     sync.Mutex
	path        string
	timeouts    config.Timeouts
	dialer      net.Dialer

	connection net.Conn
	upstream   agent.ExtendedAgent
	bindings   [][]byte
	dialCancel context.CancelFunc
	closed     bool
}

// New creates a lazy paired connection at one validated, fixed socket path.
// It deliberately does not consult SSH_AUTH_SOCK and never changes the path.
func New(path string, timeouts config.Timeouts) (*Connection, error) {
	if err := config.Validate(config.Config{Upstream: path, Timeouts: timeouts}); err != nil {
		return nil, err
	}
	return &Connection{path: path, timeouts: timeouts}, nil
}

// List applies the configured identity-list deadline to the complete upstream
// request and response.
func (connection *Connection) List() ([]*agent.Key, error) {
	var keys []*agent.Key
	err := connection.run(connection.timeouts.List, ErrList, func(upstream agent.ExtendedAgent) error {
		var err error
		keys, err = upstream.List()
		return err
	}, nil)
	return keys, err
}

// Sign applies the separate signing deadline intended to allow human approval.
func (connection *Connection) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return connection.SignWithFlags(key, data, 0)
}

// SignWithFlags preserves the requested signature flags and applies the
// separate signing deadline to the complete upstream request and response.
func (connection *Connection) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	var signature *ssh.Signature
	err := connection.run(connection.timeouts.Sign, ErrSign, func(upstream agent.ExtendedAgent) error {
		var err error
		signature, err = upstream.SignWithFlags(key, data, flags)
		return err
	}, nil)
	return signature, err
}

// Extension forwards only OpenSSH session binding. A binding enters the
// in-memory replay journal only after the upstream accepts it.
func (connection *Connection) Extension(extensionType string, contents []byte) ([]byte, error) {
	if extensionType != sessionBindExtension {
		return nil, agent.ErrExtensionUnsupported
	}

	var response []byte
	err := connection.run(connection.timeouts.Replay, ErrExtension, func(upstream agent.ExtendedAgent) error {
		var err error
		response, err = upstream.Extension(extensionType, contents)
		return err
	}, func() {
		connection.bindings = append(connection.bindings, slices.Clone(contents))
	})
	if err != nil {
		return nil, err
	}
	return response, nil
}

// Close permanently ends this pair and discards its in-memory bindings.
func (connection *Connection) Close() error {
	connection.stateMu.Lock()

	if connection.closed {
		connection.stateMu.Unlock()
		return nil
	}
	connection.closed = true
	connection.bindings = nil
	if connection.dialCancel != nil {
		connection.dialCancel()
		connection.dialCancel = nil
	}
	upstream := connection.connection
	connection.connection = nil
	connection.upstream = nil
	connection.stateMu.Unlock()

	if upstream == nil {
		return nil
	}
	if err := upstream.Close(); err != nil {
		return ErrClose
	}
	return nil
}

func (connection *Connection) run(
	timeout time.Duration,
	operationError error,
	operation func(agent.ExtendedAgent) error,
	afterSuccess func(),
) error {
	connection.operationMu.Lock()
	defer connection.operationMu.Unlock()

	upstreamConnection, upstream, err := connection.connectAndReplay()
	if err != nil {
		return err
	}
	if err := upstreamConnection.SetDeadline(time.Now().Add(timeout)); err != nil {
		connection.discard(upstreamConnection)
		return operationError
	}
	if err := operation(upstream); err != nil {
		connection.discard(upstreamConnection)
		return operationError
	}
	if err := upstreamConnection.SetDeadline(time.Time{}); err != nil {
		connection.discard(upstreamConnection)
		return operationError
	}
	connection.stateMu.Lock()
	defer connection.stateMu.Unlock()
	if connection.closed || connection.connection != upstreamConnection {
		return ErrClosed
	}
	if afterSuccess != nil {
		afterSuccess()
	}
	return nil
}

func (connection *Connection) connectAndReplay() (net.Conn, agent.ExtendedAgent, error) {
	connection.stateMu.Lock()
	if connection.closed {
		connection.stateMu.Unlock()
		return nil, nil, ErrClosed
	}
	if connection.connection != nil {
		upstreamConnection := connection.connection
		upstream := connection.upstream
		connection.stateMu.Unlock()
		return upstreamConnection, upstream, nil
	}

	dialContext, cancel := context.WithTimeout(context.Background(), connection.timeouts.Connect)
	connection.dialCancel = cancel
	connection.stateMu.Unlock()
	defer cancel()
	upstreamConnection, err := connection.dialer.DialContext(dialContext, "unix", connection.path)
	if err != nil {
		connection.stateMu.Lock()
		connection.dialCancel = nil
		closed := connection.closed
		connection.stateMu.Unlock()
		if closed {
			return nil, nil, ErrClosed
		}
		return nil, nil, ErrConnect
	}
	upstream := agent.NewClient(upstreamConnection)

	connection.stateMu.Lock()
	connection.dialCancel = nil
	if connection.closed {
		connection.stateMu.Unlock()
		_ = upstreamConnection.Close()
		return nil, nil, ErrClosed
	}
	connection.connection = upstreamConnection
	connection.upstream = upstream
	bindings := slices.Clone(connection.bindings)
	connection.stateMu.Unlock()

	if len(bindings) == 0 {
		return upstreamConnection, upstream, nil
	}
	// One deadline bounds the complete ordered replay, not each individual
	// binding, so replay cost cannot grow into an unbounded outage.
	if err := upstreamConnection.SetDeadline(time.Now().Add(connection.timeouts.Replay)); err != nil {
		connection.discard(upstreamConnection)
		return nil, nil, ErrReplay
	}
	for _, binding := range bindings {
		if _, err := upstream.Extension(sessionBindExtension, binding); err != nil {
			connection.discard(upstreamConnection)
			return nil, nil, ErrReplay
		}
	}
	if err := upstreamConnection.SetDeadline(time.Time{}); err != nil {
		connection.discard(upstreamConnection)
		return nil, nil, ErrReplay
	}
	connection.stateMu.Lock()
	defer connection.stateMu.Unlock()
	if connection.closed || connection.connection != upstreamConnection {
		return nil, nil, ErrClosed
	}
	return upstreamConnection, upstream, nil
}

func (connection *Connection) discard(upstreamConnection net.Conn) {
	connection.stateMu.Lock()
	if connection.connection == upstreamConnection {
		connection.connection = nil
		connection.upstream = nil
	}
	connection.stateMu.Unlock()
	_ = upstreamConnection.Close()
}

// Mutating and signer-producing operations are unavailable even if a caller
// bypasses the policy layer.
func (connection *Connection) Add(agent.AddedKey) error       { return ErrOperationDenied }
func (connection *Connection) Remove(ssh.PublicKey) error     { return ErrOperationDenied }
func (connection *Connection) RemoveAll() error               { return ErrOperationDenied }
func (connection *Connection) Lock([]byte) error              { return ErrOperationDenied }
func (connection *Connection) Unlock([]byte) error            { return ErrOperationDenied }
func (connection *Connection) Signers() ([]ssh.Signer, error) { return nil, ErrOperationDenied }

var _ agent.ExtendedAgent = (*Connection)(nil)
