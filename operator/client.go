// ---
// relationships:
//   implements: operator-interface
//   uses: authenticate-operator-keys-over-ssh
// ---

package operator

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/wyrd-company/wyrwood/internal/config"
)

const (
	defaultTimeout = 15 * time.Second
	defaultLabel   = "operator"
)

// Config selects a controller and the one key to present to it.
type Config struct {
	// URL is the controller's ssh://host[:port].
	URL string
	// Signer is the only key the connection offers.
	Signer ssh.Signer
	// HostKey is the controller's pinned SHA256 host-key fingerprint.
	HostKey string
	// Label is the name proposed for a pending key. The approving operator can
	// change it. It defaults to "operator".
	Label string
	// Timeout bounds the connection and each request. It defaults to 15 seconds.
	Timeout time.Duration
}

// LoginResult reports a completed login.
type LoginResult struct {
	KeyFingerprint string
	HostKey        string
	Approved       bool
}

// Login connects with the key, which records an unknown key as pending, and
// reports whether it is approved. A pending key is not an error. When config
// has no HostKey, accept decides on the presented one.
func Login(ctx context.Context, config Config, accept func(fingerprint string) bool) (LoginResult, error) {
	result := LoginResult{}
	if config.Signer != nil {
		result.KeyFingerprint = ssh.FingerprintSHA256(config.Signer.PublicKey())
	}
	client, presented, err := open(ctx, config, accept)
	result.HostKey = presented
	switch {
	case errors.Is(err, ErrNotApproved):
		return result, nil
	case err != nil:
		return result, err
	}
	result.Approved = true
	return result, client.Close()
}

// Client is one connection to the controller's operator subsystem. Requests
// run one at a time.
type Client struct {
	mu      sync.Mutex
	client  *ssh.Client
	stdin   io.WriteCloser
	stdout  *bufio.Reader
	timeout time.Duration
	conn    net.Conn
	onClose io.Closer
}

// Dial connects to the controller with a pinned host key: with no HostKey in
// config it fails with ErrHostKeyNotAccepted. A key the controller has not
// approved fails with ErrNotApproved, and an unknown key is recorded as pending.
func Dial(ctx context.Context, config Config) (*Client, error) {
	client, _, err := open(ctx, config, nil)
	return client, err
}

func open(ctx context.Context, settings Config, accept func(string) bool) (*Client, string, error) {
	address, err := config.ControllerAddress(settings.URL)
	if err != nil {
		return nil, "", ErrInvalidURL
	}
	if settings.Signer == nil {
		return nil, "", ErrLoginState
	}
	if settings.Timeout == 0 {
		settings.Timeout = defaultTimeout
	}
	if settings.Label == "" {
		settings.Label = defaultLabel
	}
	if !ValidLabel(settings.Label) {
		return nil, "", fmt.Errorf("%w: label", ErrInvalid)
	}
	var presented string
	var hostKeyFailure error
	callback := func(_ string, _ net.Addr, key ssh.PublicKey) error {
		presented = ssh.FingerprintSHA256(key)
		switch {
		case settings.HostKey != "":
			if settings.HostKey != presented {
				hostKeyFailure = ErrHostKeyMismatch
			}
		case accept == nil || !accept(presented):
			hostKeyFailure = ErrHostKeyNotAccepted
		}
		return hostKeyFailure
	}
	dialer := net.Dialer{Timeout: settings.Timeout}
	connection, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, "", ErrUnreachable
	}
	_ = connection.SetDeadline(time.Now().Add(settings.Timeout))
	stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stop()
	clientConnection, channels, requests, err := ssh.NewClientConn(connection, address, &ssh.ClientConfig{
		User: User(settings.Label), Auth: []ssh.AuthMethod{ssh.PublicKeys(settings.Signer)}, HostKeyCallback: callback,
	})
	if err != nil {
		_ = connection.Close()
		switch {
		case hostKeyFailure != nil:
			return nil, presented, hostKeyFailure
		case presented != "" && strings.Contains(err.Error(), "unable to authenticate"):
			return nil, presented, ErrNotApproved
		default:
			return nil, presented, ErrUnreachable
		}
	}
	client := ssh.NewClient(clientConnection, channels, requests)
	session, err := client.NewSession()
	if err != nil {
		_ = client.Close()
		return nil, presented, ErrUnreachable
	}
	stdin, err := session.StdinPipe()
	if err != nil {
		_ = client.Close()
		return nil, presented, ErrUnreachable
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		_ = client.Close()
		return nil, presented, ErrUnreachable
	}
	if err := session.RequestSubsystem(SubsystemName); err != nil {
		_ = client.Close()
		return nil, presented, ErrUnreachable
	}
	_ = connection.SetDeadline(time.Time{})
	return &Client{
		client: client, stdin: stdin, stdout: bufio.NewReaderSize(stdout, 64<<10),
		timeout: settings.Timeout, conn: connection,
	}, presented, nil
}

// Close ends the connection.
func (client *Client) Close() error {
	err := client.client.Close()
	if err != nil && errors.Is(err, net.ErrClosed) {
		err = nil
	}
	if client.onClose != nil {
		err = errors.Join(err, client.onClose.Close())
	}
	return err
}

// Request is one line a client sends.
type Request struct {
	Version   int             `json:"version"`
	Operation Operation       `json:"operation"`
	Body      json.RawMessage `json:"body,omitempty"`
}

// Response is one line the controller answers with.
type Response struct {
	Version int             `json:"version"`
	Body    json.RawMessage `json:"body,omitempty"`
	Error   *Error          `json:"error,omitempty"`
}

func (client *Client) call(ctx context.Context, operation Operation, body, result any) error {
	client.mu.Lock()
	defer client.mu.Unlock()
	request := Request{Version: ProtocolVersion, Operation: operation}
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("%w: encode request", ErrInvalid)
		}
		request.Body = encoded
	}
	line, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("%w: encode request", ErrInvalid)
	}
	if len(line) >= MaximumLineBytes {
		return fmt.Errorf("%w: the request exceeds 1 MiB", ErrInvalid)
	}
	_ = client.conn.SetDeadline(time.Now().Add(client.timeout))
	defer func() { _ = client.conn.SetDeadline(time.Time{}) }()
	stop := context.AfterFunc(ctx, func() { _ = client.conn.Close() })
	defer stop()
	if _, err := client.stdin.Write(append(line, '\n')); err != nil {
		return ErrUnreachable
	}
	reply, err := ReadLine(client.stdout, MaximumResponseBytes)
	if err != nil {
		return ErrUnreachable
	}
	var response Response
	if err := json.Unmarshal(reply, &response); err != nil || response.Version != ProtocolVersion {
		return fmt.Errorf("%w: unreadable response", ErrFailed)
	}
	if response.Error != nil {
		return response.Error
	}
	if result == nil {
		return nil
	}
	if err := json.Unmarshal(response.Body, result); err != nil {
		return fmt.Errorf("%w: unreadable response", ErrFailed)
	}
	return nil
}

// ReadLine reads one protocol line of less than limit bytes, without its newline.
func ReadLine(reader *bufio.Reader, limit int) ([]byte, error) {
	var line []byte
	for {
		fragment, err := reader.ReadSlice('\n')
		line = append(line, fragment...)
		if len(line) >= limit {
			return nil, errors.New("line exceeds its limit")
		}
		switch {
		case err == nil:
			return line[:len(line)-1], nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		default:
			return nil, err
		}
	}
}

// Whoami returns this key's label and grant. It needs no action in the grant.
func (client *Client) Whoami(ctx context.Context) (Identity, error) {
	var result Identity
	err := client.call(ctx, OperationWhoami, nil, &result)
	return result, err
}

// ListPolicies returns the policies inside the grant. It needs ActionRead.
func (client *Client) ListPolicies(ctx context.Context) ([]Policy, error) {
	var result Policies
	err := client.call(ctx, OperationPolicyList, nil, &result)
	return result.Policies, err
}

// GetPolicy returns one policy. It needs ActionRead.
func (client *Client) GetPolicy(ctx context.Context, name string) (Policy, error) {
	var result Policy
	err := client.call(ctx, OperationPolicyGet, PolicyName{Name: name}, &result)
	return result, err
}

// PutPolicy creates or changes a policy. It needs ActionPolicyWrite. Putting the
// same source again changes nothing. A policy that a binding outside the grant
// holds fails with ErrOutsideGrant, since the change would reach that binding.
func (client *Client) PutPolicy(ctx context.Context, put PolicyPut) (Policy, error) {
	var result Policy
	err := client.call(ctx, OperationPolicyPut, put, &result)
	return result, err
}

// ListBindings returns the bindings inside the grant with their readiness. It
// needs ActionRead. A binding that holds a policy outside the grant is left out.
func (client *Client) ListBindings(ctx context.Context, selection BindingList) ([]Binding, error) {
	var result Bindings
	err := client.call(ctx, OperationBindingList, selection, &result)
	return result.Bindings, err
}

// GetBinding returns one binding with its readiness. It needs ActionRead.
func (client *Client) GetBinding(ctx context.Context, id string) (Binding, error) {
	var result Binding
	err := client.call(ctx, OperationBindingGet, BindingID{ID: id}, &result)
	return result, err
}

// Bind returns the binding of a container key, creating it when absent. It
// needs ActionBind. It is safe to repeat. See BindRequest.
func (client *Client) Bind(ctx context.Context, request BindRequest) (Binding, error) {
	var result Binding
	err := client.call(ctx, OperationBind, request, &result)
	return result, err
}

// Unbind removes a binding. It needs ActionBind. A binding that does not exist
// is a success, so it is safe to repeat.
func (client *Client) Unbind(ctx context.Context, request UnbindRequest) (UnbindResult, error) {
	var result UnbindResult
	err := client.call(ctx, OperationUnbind, request, &result)
	return result, err
}
