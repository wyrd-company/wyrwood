// ---
// relationships:
//   implements:
//     - agent
//     - agent-controller-protocol
// ---

package agent

import (
	"context"
	"errors"
	"io"
	"net"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/wyrd-company/wyrwood/internal/protocol"
)

// outboundQueue bounds messages waiting for the controller. A full queue
// closes the session; the reconnect resends the complete state.
const outboundQueue = 1024

type controllerSession struct {
	conn   *protocol.Conn
	closer io.Closer
	queue  chan protocol.Message
	done   chan struct{}
	// sent observes each message the controller connection accepted.
	sent func(protocol.Message)
}

func newControllerSession(conn *protocol.Conn, closer io.Closer, sent func(protocol.Message)) *controllerSession {
	return &controllerSession{conn: conn, closer: closer, queue: make(chan protocol.Message, outboundQueue),
		done: make(chan struct{}), sent: sent}
}

// send enqueues a message without blocking; messages reach the controller
// in the order they were sent.
func (session *controllerSession) send(message protocol.Message) {
	select {
	case <-session.done:
	case session.queue <- message:
	default:
		_ = session.closer.Close()
	}
}

func (session *controllerSession) write() {
	for {
		select {
		case <-session.done:
			return
		case message := <-session.queue:
			if err := session.conn.Send(message); err != nil {
				_ = session.closer.Close()
				return
			}
			session.sent(message)
		}
	}
}

// runController keeps one session to the controller with bounded
// exponential backoff until ctx ends.
func (agent *Agent) runController(ctx context.Context) {
	delay := time.Second
	for ctx.Err() == nil {
		connected, err := agent.connectOnce(ctx)
		if connected {
			delay = time.Second
		}
		if err != nil && ctx.Err() == nil {
			agent.logf("controller session ended (%s)", sessionCategory(err))
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		if delay < time.Minute {
			delay *= 2
		}
	}
}

var errHostKey = errors.New("controller host key does not match")

func sessionCategory(err error) string {
	switch {
	case errors.Is(err, errHostKey):
		return "host-key-mismatch"
	case errors.Is(err, protocol.ErrInvalid), errors.Is(err, protocol.ErrLineTooLong):
		return "protocol"
	default:
		return "unavailable"
	}
}

func (agent *Agent) connectOnce(ctx context.Context) (bool, error) {
	signer, err := LoadKey(agent.paths)
	if err != nil {
		return false, err
	}
	known, err := LoadKnownController(agent.paths)
	if err != nil || known.URL != agent.config.ControllerURL {
		return false, errHostKey
	}
	dialer := net.Dialer{Timeout: agent.config.ControllerTimeout}
	connection, err := dialer.DialContext(ctx, "tcp", agent.config.ControllerAddress)
	if err != nil {
		return false, err
	}
	_ = connection.SetDeadline(time.Now().Add(agent.config.ControllerTimeout))
	clientConnection, channels, requests, err := ssh.NewClientConn(connection, agent.config.ControllerAddress, &ssh.ClientConfig{
		User: agent.hostname, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			if ssh.FingerprintSHA256(key) != known.Fingerprint {
				return errHostKey
			}
			return nil
		},
	})
	if err != nil {
		_ = connection.Close()
		if errors.Is(err, errHostKey) {
			return false, errHostKey
		}
		return false, err
	}
	client := ssh.NewClient(clientConnection, channels, requests)
	defer client.Close()
	channel, err := client.NewSession()
	if err != nil {
		return false, err
	}
	stdin, err := channel.StdinPipe()
	if err != nil {
		return false, err
	}
	stdout, err := channel.StdoutPipe()
	if err != nil {
		return false, err
	}
	if err := channel.RequestSubsystem(protocol.SubsystemName); err != nil {
		return false, err
	}
	_ = connection.SetDeadline(time.Time{})
	session := newControllerSession(protocol.NewConn(readWriter{Reader: stdout, Writer: stdin}), client, agent.resultSent)
	defer close(session.done)
	if err := session.conn.Send(protocol.Hello{AgentVersion: Version, AllowRecreate: agent.config.AllowRecreate}); err != nil {
		return false, err
	}
	go session.write()
	agent.mu.Lock()
	agent.session = session
	agent.connected = true
	results := make([]protocol.ContractResult, 0, len(agent.results))
	for _, result := range agent.results {
		results = append(results, result)
	}
	agent.mu.Unlock()
	defer func() {
		agent.mu.Lock()
		if agent.session == session {
			agent.session = nil
			agent.connected = false
		}
		agent.mu.Unlock()
	}()
	stop := context.AfterFunc(ctx, func() { _ = client.Close() })
	defer stop()
	agent.sendInventory()
	for _, result := range results {
		session.send(result)
	}
	for {
		message, err := session.conn.Receive()
		if err != nil {
			return true, err
		}
		agent.mu.Lock()
		agent.lastReport = time.Now()
		agent.mu.Unlock()
		switch typed := message.(type) {
		case protocol.PolicySet:
			agent.applyPolicySet(ctx, typed)
		case protocol.Credential:
			go agent.creds.deliver(ctx, typed, agent.creds.begin(typed.Binding))
		case protocol.RecreateRequest:
			agent.requestRecreate(ctx, typed.Binding)
		case protocol.Unbind:
			agent.unbind(ctx, typed.Binding)
		default:
			return true, protocol.ErrInvalid
		}
	}
}

type readWriter struct {
	io.Reader
	io.Writer
}
