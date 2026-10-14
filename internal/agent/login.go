// ---
// relationships:
//   implements:
//     - agent
//     - command-line-interface
//   uses: enroll-agents-with-host-generated-keys
// ---

package agent

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/wyrd-company/wyrwood/internal/config"
)

// Categorical login failures.
var (
	ErrInvalidURL      = errors.New("controller URL is invalid")
	ErrLoginState      = errors.New("agent key or login state unavailable")
	ErrUnreachable     = errors.New("controller unreachable")
	ErrHostKeyMismatch = errors.New("controller host-key fingerprint does not match")
	ErrNotAccepted     = errors.New("controller host-key fingerprint was not accepted")
)

// LoginResult reports a completed login.
type LoginResult struct {
	AgentFingerprint      string
	ControllerFingerprint string
	Approved              bool
}

// LoginOptions configure a login.
type LoginOptions struct {
	Paths             Paths
	ControllerURL     string
	AcceptFingerprint string
	// Announce receives the agent key fingerprint before connecting.
	Announce func(agentFingerprint string)
	// Confirm asks the operator to accept a controller fingerprint when no
	// fingerprint was supplied and none was accepted for this URL before.
	Confirm  func(controllerFingerprint string) bool
	Hostname func() (string, error)
	Timeout  time.Duration
}

// Login creates the agent key when absent, pins the controller host key,
// records the controller URL, and reports whether the key is approved.
func Login(ctx context.Context, options LoginOptions) (LoginResult, error) {
	address, err := config.ControllerAddress(options.ControllerURL)
	if err != nil {
		return LoginResult{}, ErrInvalidURL
	}
	if options.Hostname == nil {
		options.Hostname = os.Hostname
	}
	if options.Timeout == 0 {
		options.Timeout = 15 * time.Second
	}
	hostname, err := options.Hostname()
	if err != nil || hostname == "" {
		return LoginResult{}, ErrLoginState
	}
	signer, _, err := LoadOrCreateKey(options.Paths)
	if err != nil {
		return LoginResult{}, ErrLoginState
	}
	result := LoginResult{AgentFingerprint: ssh.FingerprintSHA256(signer.PublicKey())}
	if options.Announce != nil {
		options.Announce(result.AgentFingerprint)
	}
	known, knownErr := LoadKnownController(options.Paths)
	if knownErr != nil && !errors.Is(knownErr, os.ErrNotExist) {
		return LoginResult{}, ErrLoginState
	}

	var hostKeyFailure error
	callback := func(_ string, _ net.Addr, key ssh.PublicKey) error {
		presented := ssh.FingerprintSHA256(key)
		result.ControllerFingerprint = presented
		switch {
		case options.AcceptFingerprint != "":
			if options.AcceptFingerprint != presented {
				hostKeyFailure = ErrHostKeyMismatch
			}
		case knownErr == nil && known.URL == options.ControllerURL:
			if known.Fingerprint != presented {
				hostKeyFailure = ErrHostKeyMismatch
			}
		case options.Confirm == nil || !options.Confirm(presented):
			hostKeyFailure = ErrNotAccepted
		}
		return hostKeyFailure
	}
	dialer := net.Dialer{Timeout: options.Timeout}
	connection, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return result, ErrUnreachable
	}
	// The timeout and ctx bound the SSH handshake as well as the dial.
	_ = connection.SetDeadline(time.Now().Add(options.Timeout))
	stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
	clientConnection, channels, requests, err := ssh.NewClientConn(connection, address, &ssh.ClientConfig{
		User: hostname, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: callback,
	})
	stop()
	approved := err == nil
	if approved {
		_ = ssh.NewClient(clientConnection, channels, requests).Close()
	} else {
		_ = connection.Close()
		switch {
		case hostKeyFailure != nil:
			return result, hostKeyFailure
		case result.ControllerFingerprint == "" || !strings.Contains(err.Error(), "unable to authenticate"):
			return result, ErrUnreachable
		}
	}
	if err := SaveKnownController(options.Paths, KnownControllerRecord{URL: options.ControllerURL, Fingerprint: result.ControllerFingerprint}); err != nil {
		return result, ErrLoginState
	}
	if err := config.WriteAgentControllerURL(options.Paths.Config, options.ControllerURL); err != nil {
		return result, ErrLoginState
	}
	handOver(options.Paths)
	result.Approved = approved
	return result, nil
}
