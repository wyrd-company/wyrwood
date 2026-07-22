//go:build linux

// ---
// relationships:
//   verifies: terminal-interface
//   uses: control-interface
// ---

package tui

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/wyrd-company/wyrwood/internal/control"
)

func TestRealControlSocketConfigurationConflictAndDegradedApply(t *testing.T) {
	server := newWorkflowControlServer(t)
	defer server.close()
	transport, err := control.NewClient(server.path)
	if err != nil {
		t.Fatal(err)
	}
	model := NewModel(NewControlClient(transport), options{Schedule: noSchedule})
	runAllCommands(model, model.Init())
	if model.configurationState != loadReady || model.keysState != loadUnavailable || len(model.consumers) != 1 {
		t.Fatalf("real startup states = configuration %s, keys %s, consumers %d", model.configurationState, model.keysState, len(model.consumers))
	}

	model.Update(key("s"))
	model.editor.inputs[0].SetValue("6s")
	model.editor.syncDirty()
	model.editor.validate(model)
	model.editor.setFocus(model.editor.saveFocus())
	_, command := model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	runAllCommands(model, command)
	if model.configuration.Revision != strings.Repeat("2", 64) || model.configuration.Timeouts.Connect != "6s" {
		t.Fatalf("saved real configuration = %#v", model.configuration)
	}

	rival, err := control.NewClient(server.path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rival.SetUpstream(strings.Repeat("2", 64), "/tmp/example/alternate.sock"); err != nil {
		t.Fatal(err)
	}
	model.Update(key("s"))
	model.editor.inputs[1].SetValue("7s")
	model.editor.syncDirty()
	model.editor.validate(model)
	model.editor.setFocus(model.editor.saveFocus())
	_, command = model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	runAllCommands(model, command)
	if !model.editor.conflict || model.editor.inputs[1].Value() != "7s" || !strings.Contains(model.View(), "CONFLICT") {
		t.Fatalf("real stale revision did not preserve candidate: %#v\n%s", model.editor, model.View())
	}

	model.modal = modalDiscard
	model.Update(key("d"))
	_, command = model.Update(key("a"))
	runAllCommands(model, command)
	if !strings.Contains(model.notice, "COMMITTED DEGRADED") || !strings.Contains(model.notice, "cleanup 2") || model.status.ActiveRevision != strings.Repeat("3", 64) {
		t.Fatalf("real degraded apply = notice %q, status %#v", model.notice, model.status)
	}
}

type workflowControlServer struct {
	t        *testing.T
	path     string
	listener net.Listener
	done     chan struct{}
	once     sync.Once
	mu       sync.Mutex
	revision string
	active   string
	upstream string
	timeouts control.ConfigurationTimeouts
}

func newWorkflowControlServer(t *testing.T) *workflowControlServer {
	t.Helper()
	path := filepath.Join(t.TempDir(), "control.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	server := &workflowControlServer{
		t: t, path: path, listener: listener, done: make(chan struct{}),
		revision: strings.Repeat("1", 64), active: strings.Repeat("1", 64), upstream: "/tmp/example/source.sock",
		timeouts: control.ConfigurationTimeouts{Connect: "1s", List: "2s", Replay: "3s", Sign: "4s"},
	}
	go server.serve()
	return server
}

func (server *workflowControlServer) close() {
	server.once.Do(func() {
		_ = server.listener.Close()
		<-server.done
	})
}

func (server *workflowControlServer) serve() {
	defer close(server.done)
	for {
		connection, err := server.listener.Accept()
		if err != nil {
			return
		}
		server.handle(connection)
		_ = connection.Close()
	}
}

func (server *workflowControlServer) handle(connection net.Conn) {
	var size uint32
	if err := binary.Read(connection, binary.BigEndian, &size); err != nil || size == 0 || size > control.MaximumRequestBytes {
		return
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(connection, data); err != nil {
		return
	}
	var request control.Request
	if err := json.Unmarshal(data, &request); err != nil {
		return
	}
	response := server.response(request)
	payload, err := json.Marshal(response)
	if err != nil {
		server.t.Errorf("marshal response: %v", err)
		return
	}
	frame := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(payload)))
	copy(frame[4:], payload)
	if _, err := connection.Write(frame); err != nil {
		server.t.Errorf("write response: %v", err)
	}
}

func (server *workflowControlServer) response(request control.Request) control.Response {
	server.mu.Lock()
	defer server.mu.Unlock()
	success := control.Response{Version: control.Version, OK: true, Error: control.ErrorNone}
	consumerSocket := "/tmp/example/alpha/agent.sock"
	consumerDigest := sha256.Sum256([]byte(consumerSocket))
	consumerID := hex.EncodeToString(consumerDigest[:])
	switch request.Operation {
	case control.OperationConfiguration:
		success.Configuration = &control.ConfigurationResult{
			Revision: server.revision, Upstream: server.upstream, Timeouts: server.timeouts,
			TotalConsumers: 1, Complete: true,
			Consumers: []control.ConfigurationConsumer{{ID: consumerID, ConfigurationConsumerInput: control.ConfigurationConsumerInput{
				Name: "sample alpha", Socket: consumerSocket, Fingerprints: []string{sampleFingerprint},
			}}},
		}
	case control.OperationKeys:
		return control.Response{Version: control.Version, OK: false, Error: control.ErrorUpstreamUnavailable}
	case control.OperationStatus:
		success.Status = &control.StatusResult{
			ActiveRevision: server.active, Daemon: control.HealthHealthy, Upstream: control.HealthUnavailable,
			Consumers: []control.ConsumerStatus{{ID: consumerID, Name: "sample alpha", Listener: control.HealthHealthy}},
		}
	case control.OperationEvents:
		success.Events = &control.EventsResult{Events: []control.Event{}}
	case control.OperationSetTimeouts:
		if request.ExpectedRevision == nil || *request.ExpectedRevision != server.revision {
			return control.Response{Version: control.Version, OK: false, Error: control.ErrorConfigurationConflict}
		}
		server.timeouts = *request.Timeouts
		server.revision = nextIntegrationRevision(server.revision)
		success.ConfigurationChange = &control.ConfigurationChangeResult{Operation: request.Operation, Revision: server.revision, Changed: true}
	case control.OperationSetUpstream:
		if request.ExpectedRevision == nil || *request.ExpectedRevision != server.revision {
			return control.Response{Version: control.Version, OK: false, Error: control.ErrorConfigurationConflict}
		}
		server.upstream = *request.Upstream
		server.revision = nextIntegrationRevision(server.revision)
		success.ConfigurationChange = &control.ConfigurationChangeResult{Operation: request.Operation, Revision: server.revision, Changed: true}
	case control.OperationApply:
		server.active = server.revision
		success.Apply = &control.ApplyResult{Revision: server.active, Committed: true, Degraded: true, PendingCleanup: 2, PendingPermissions: 1}
	default:
		return control.Response{Version: control.Version, OK: false, Error: control.ErrorBadRequest}
	}
	return success
}

func nextIntegrationRevision(revision string) string {
	if revision == strings.Repeat("1", 64) {
		return strings.Repeat("2", 64)
	}
	return strings.Repeat("3", 64)
}
