// ---
// relationships:
//   implements:
//     - agent
//     - command-line-interface
//   uses: operational-events
// ---

package agent

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/wyrd-company/wyrwood/internal/contract"
	"github.com/wyrd-company/wyrwood/internal/events"
	"github.com/wyrd-company/wyrwood/internal/protocol"
)

// ControlVersion is the control protocol and projection version.
const ControlVersion = 2

const maximumControlRequestBytes = 4096

// ControlRequest is one control request.
type ControlRequest struct {
	Version   int    `json:"version"`
	Operation string `json:"operation"`
	Limit     int    `json:"limit,omitempty"`
}

// Status is the status projection.
type Status struct {
	Version    int            `json:"version"`
	Agent      string         `json:"agent"`
	Controller string         `json:"controller"`
	Session    string         `json:"session"`
	Containers int            `json:"containers"`
	Bindings   int            `json:"bindings"`
	Tokens     int            `json:"tokens"`
	Health     map[string]int `json:"health"`
}

// ContainerStatus is one entry of the containers projection.
type ContainerStatus struct {
	Name             string                `json:"name"`
	State            string                `json:"state"`
	BindingKey       string                `json:"binding-key,omitempty"`
	Policies         []string              `json:"policies"`
	Assignment       string                `json:"assignment,omitempty"`
	Conformance      string                `json:"conformance"`
	Token            string                `json:"token"`
	AccessGroupError string                `json:"access-group-error,omitempty"`
	FailedItems      []protocol.FailedItem `json:"failed-items,omitempty"`
}

// Containers is the containers projection.
type Containers struct {
	Version    int               `json:"version"`
	Containers []ContainerStatus `json:"containers"`
}

// Events is the events projection.
type Events struct {
	Version int             `json:"version"`
	Events  []events.Record `json:"events"`
}

type controlError struct {
	Version int    `json:"version"`
	Error   string `json:"error"`
}

func (agent *Agent) listenControl() (net.Listener, error) {
	listener, err := listenControlSocket(agent.paths.ControlSocket(), net.ListenUnix)
	if err != nil {
		return nil, err
	}
	go agent.serveControl(listener)
	return listener, nil
}

// Bind privately, then publish the secured socket without changing process umask.
func listenControlSocket(path string, bind func(string, *net.UnixAddr) (*net.UnixListener, error)) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	var status unix.Stat_t
	if err := unix.Lstat(path, &status); err == nil {
		if status.Mode&unix.S_IFMT != unix.S_IFSOCK || status.Uid != uint32(os.Geteuid()) {
			return nil, errors.New("control socket path is occupied")
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	}
	// A private directory prevents access even before the socket is chmodded.
	stage, err := os.MkdirTemp(filepath.Dir(path), ".control-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(stage)
	directory, err := os.Open(stage)
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	// Keep the bind address short independently of the runtime directory length.
	address := fmt.Sprintf("/proc/self/fd/%d/socket", directory.Fd())
	listener, err := bind("unix", &net.UnixAddr{Name: address, Net: "unix"})
	if err != nil {
		return nil, err
	}
	listener.SetUnlinkOnClose(false)
	staged := filepath.Join(stage, "socket")
	if err := os.Chmod(staged, 0o600); err != nil {
		_ = listener.Close()
		return nil, err
	}
	info, err := os.Lstat(staged)
	if err != nil {
		_ = listener.Close()
		return nil, err
	}
	if err := os.Rename(staged, path); err != nil {
		_ = listener.Close()
		return nil, err
	}
	return &controlListener{Listener: listener, path: path, info: info}, nil
}

type controlListener struct {
	net.Listener
	path string
	info os.FileInfo
	once sync.Once
}

func (listener *controlListener) Close() error {
	err := listener.Listener.Close()
	listener.once.Do(func() {
		if info, statErr := os.Lstat(listener.path); statErr == nil && os.SameFile(info, listener.info) {
			_ = os.Remove(listener.path)
		}
	})
	return err
}

func (agent *Agent) serveControl(listener net.Listener) {
	for {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		go agent.handleControl(connection)
	}
}

func (agent *Agent) handleControl(connection net.Conn) {
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(10 * time.Second))
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok || !authorizedPeer(unixConnection) {
		return
	}
	reader := bufio.NewReader(&limitedReader{reader: connection, remaining: maximumControlRequestBytes})
	line, err := reader.ReadBytes('\n')
	if err != nil {
		return
	}
	var request ControlRequest
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.DisallowUnknownFields()
	encoder := json.NewEncoder(connection)
	if decoder.Decode(&request) != nil || request.Version != ControlVersion {
		_ = encoder.Encode(controlError{Version: ControlVersion, Error: "invalid-request"})
		return
	}
	switch request.Operation {
	case "status":
		_ = encoder.Encode(agent.Status())
	case "containers":
		_ = encoder.Encode(agent.ContainerStatuses())
	case "events":
		if request.Limit < 1 || request.Limit > 1000 {
			_ = encoder.Encode(controlError{Version: ControlVersion, Error: "invalid-request"})
			return
		}
		_ = encoder.Encode(agent.RecentEvents(request.Limit))
	default:
		_ = encoder.Encode(controlError{Version: ControlVersion, Error: "invalid-request"})
	}
}

func authorizedPeer(connection *net.UnixConn) bool {
	raw, err := connection.SyscallConn()
	if err != nil {
		return false
	}
	var credential *unix.Ucred
	var credentialErr error
	if err := raw.Control(func(fd uintptr) {
		credential, credentialErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil || credentialErr != nil {
		return false
	}
	return credential.Uid == 0 || credential.Uid == uint32(os.Geteuid())
}

// Status returns the status projection.
func (agent *Agent) Status() Status {
	health := map[string]int{}
	for _, category := range agent.events.BindingHealth() {
		health[string(category)]++
	}
	tokens := 0
	for _, valid := range agent.creds.holding() {
		if valid {
			tokens++
		}
	}
	agent.mu.Lock()
	defer agent.mu.Unlock()
	session := "disconnected"
	if agent.connected {
		session = "connected"
	}
	return Status{
		Version: ControlVersion, Agent: agent.hostname, Controller: agent.config.ControllerURL, Session: session,
		Containers: len(agent.containers), Bindings: len(agent.set.Bindings), Tokens: tokens, Health: health,
	}
}

// ContainerStatuses returns the containers projection.
func (agent *Agent) ContainerStatuses() Containers {
	holding := agent.creds.holding()
	agent.mu.Lock()
	defer agent.mu.Unlock()
	result := Containers{Version: ControlVersion, Containers: []ContainerStatus{}}
	for _, container := range agent.containers {
		entry := ContainerStatus{Policies: []string{}, Name: container.ShortName(), State: container.State.Status, Conformance: "not-bound", Token: "none"}
		if bound, ok := agent.governingLocked(container); ok {
			entry.BindingKey = events.ContainerKey(string(bound.Key.Kind), bound.Key.Value)
			entry.Policies = bound.Policy.Names()
			entry.Assignment = bound.Assignment
			entry.Conformance = "unknown"
			if result, ok := agent.results[bound.Binding]; ok {
				entry.Conformance = string(result.Outcome)
				for _, item := range result.FailedItems {
					if item == protocol.FailedAccessGroup && bound.Policy.Contract.AccessGroup != nil {
						entry.AccessGroupError = contract.UnassignableGroup(*bound.Policy.Contract.AccessGroup)
					}
				}
				entry.FailedItems = append([]protocol.FailedItem(nil), result.FailedItems...)
			}
			if valid, ok := holding[bound.Binding]; ok && valid {
				entry.Token = "valid"
			} else if ok {
				entry.Token = "expired"
			}
		}
		result.Containers = append(result.Containers, entry)
	}
	sort.Slice(result.Containers, func(left, right int) bool {
		return result.Containers[left].Name < result.Containers[right].Name
	})
	return result
}

// RecentEvents returns the events projection, newest last.
func (agent *Agent) RecentEvents(limit int) Events {
	recent := agent.events.Recent(limit)
	result := Events{Version: ControlVersion, Events: make([]events.Record, 0, len(recent))}
	for _, event := range recent {
		result.Events = append(result.Events, event.Record())
	}
	return result
}

// ErrControlUnavailable means the daemon's control socket did not answer.
var ErrControlUnavailable = errors.New("agent daemon control socket unavailable")

// Query sends one control request and decodes the response into destination.
func Query(ctx context.Context, paths Paths, request ControlRequest, destination any) error {
	var dialer net.Dialer
	connection, err := dialer.DialContext(ctx, "unix", paths.ControlSocket())
	if err != nil {
		return ErrControlUnavailable
	}
	defer connection.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	request.Version = ControlVersion
	if err := json.NewEncoder(connection).Encode(request); err != nil {
		return ErrControlUnavailable
	}
	line, err := bufio.NewReader(connection).ReadBytes('\n')
	if err != nil {
		return ErrControlUnavailable
	}
	var failure controlError
	if json.Unmarshal(line, &failure) == nil && failure.Error != "" {
		return ErrControlUnavailable
	}
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return ErrControlUnavailable
	}
	return nil
}

type limitedReader struct {
	reader    interface{ Read([]byte) (int, error) }
	remaining int
}

func (reader *limitedReader) Read(data []byte) (int, error) {
	if reader.remaining <= 0 {
		return 0, errors.New("request too large")
	}
	if len(data) > reader.remaining {
		data = data[:reader.remaining]
	}
	count, err := reader.reader.Read(data)
	reader.remaining -= count
	return count, err
}
