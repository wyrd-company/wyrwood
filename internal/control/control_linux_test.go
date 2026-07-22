//go:build linux

// ---
// relationships:
//   verifies: control-interface
// ---

package control

import (
	"encoding/binary"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

type testHandler struct{ calls atomic.Int64 }

func (handler *testHandler) Apply() (ApplyResult, ErrorCode) {
	handler.calls.Add(1)
	return ApplyResult{Committed: true}, ErrorNone
}
func (handler *testHandler) Keys() (KeysResult, ErrorCode) {
	handler.calls.Add(1)
	return KeysResult{Keys: []Key{}}, ErrorNone
}
func (handler *testHandler) Status() (StatusResult, ErrorCode) {
	handler.calls.Add(1)
	return StatusResult{Daemon: HealthHealthy, Upstream: HealthUnavailable, Consumers: []ConsumerStatus{}}, ErrorNone
}
func (handler *testHandler) Events(int) (EventsResult, ErrorCode) {
	handler.calls.Add(1)
	return EventsResult{Events: []Event{}}, ErrorNone
}

func TestUnixControlServerAuthenticatesKernelPeerAndUsesOwnerOnlyModes(t *testing.T) {
	path := controlPath(t)
	handler := &testHandler{}
	server, err := Listen(path, uint32(os.Geteuid()), handler)
	if err != nil {
		t.Fatalf("Listen(): %v", err)
	}
	defer server.Close()
	assertPermission(t, filepath.Dir(path), 0o700)
	assertPermission(t, path, 0o600)

	client, err := NewClient(path)
	if err != nil {
		t.Fatalf("NewClient(): %v", err)
	}
	status, err := client.Status()
	if err != nil {
		t.Fatalf("Status(): %v", err)
	}
	if status.Daemon != HealthHealthy || handler.calls.Load() != 1 {
		t.Fatalf("status = %#v, calls = %d", status, handler.calls.Load())
	}
}

func TestUnixControlServerRejectsUnauthorizedPeerBeforeDecoding(t *testing.T) {
	path := controlPath(t)
	handler := &testHandler{}
	server, err := listenWithPeerCredential(path, uint32(os.Geteuid()), handler, func(*net.UnixConn) (uint32, error) {
		return uint32(os.Geteuid()) + 1, nil
	})
	if err != nil {
		t.Fatalf("listenWithPeerCredential(): %v", err)
	}
	defer server.Close()
	connection, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatalf("DialUnix(): %v", err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(time.Second))
	if err := writeJSONFrame(connection, MaximumRequestBytes, Request{Version: Version, Operation: OperationStatus}); err != nil {
		t.Fatalf("writeJSONFrame(): %v", err)
	}
	var response Response
	if err := readJSONFrame(connection, MaximumResponseBytes, &response); err == nil {
		t.Fatalf("unauthorized peer received response %#v", response)
	}
	if handler.calls.Load() != 0 {
		t.Fatalf("unauthorized peer reached handler %d times", handler.calls.Load())
	}
}

func TestControlProtocolRejectsMalformedOversizedUnknownAndMismatchedRequests(t *testing.T) {
	path := controlPath(t)
	handler := &testHandler{}
	server, err := Listen(path, uint32(os.Geteuid()), handler)
	if err != nil {
		t.Fatalf("Listen(): %v", err)
	}
	defer server.Close()

	tests := []struct {
		name     string
		body     []byte
		declared uint32
		want     ErrorCode
	}{
		{name: "malformed", body: []byte(`{"version":`), declared: 11, want: ErrorBadRequest},
		{name: "unknown field", body: []byte(`{"version":1,"operation":"status","extra":true}`), want: ErrorBadRequest},
		{name: "duplicate field", body: []byte(`{"version":1,"version":1,"operation":"status"}`), want: ErrorBadRequest},
		{name: "unknown operation", body: []byte(`{"version":1,"operation":"remove"}`), want: ErrorBadRequest},
		{name: "version", body: []byte(`{"version":2,"operation":"status"}`), want: ErrorUnsupportedVersion},
		{name: "oversized", declared: MaximumRequestBytes + 1, want: ErrorBadRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			connection, err := net.Dial("unix", path)
			if err != nil {
				t.Fatalf("Dial(): %v", err)
			}
			defer connection.Close()
			length := test.declared
			if length == 0 {
				length = uint32(len(test.body))
			}
			var header [4]byte
			binary.BigEndian.PutUint32(header[:], length)
			if _, err := connection.Write(header[:]); err != nil {
				t.Fatalf("write header: %v", err)
			}
			if len(test.body) > 0 {
				if _, err := connection.Write(test.body); err != nil {
					t.Fatalf("write body: %v", err)
				}
			}
			var response Response
			if err := readJSONFrame(connection, MaximumResponseBytes, &response); err != nil {
				t.Fatalf("read response: %v", err)
			}
			if response.OK || response.Error != test.want {
				t.Fatalf("response = %#v, want %s", response, test.want)
			}
		})
	}
	if handler.calls.Load() != 0 {
		t.Fatalf("rejected requests reached handler %d times", handler.calls.Load())
	}
}

func TestControlListenerRecoversStaleSocketRejectsLiveDaemonAndCleansResources(t *testing.T) {
	path := controlPath(t)
	stale, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatalf("create stale listener: %v", err)
	}
	stale.SetUnlinkOnClose(false)
	if err := stale.Close(); err != nil {
		t.Fatalf("close stale listener: %v", err)
	}

	server, err := Listen(path, uint32(os.Geteuid()), &testHandler{})
	if err != nil {
		t.Fatalf("recover stale listener: %v", err)
	}
	if _, err := Listen(path, uint32(os.Geteuid()), &testHandler{}); !errors.Is(err, ErrAlreadyRunning) {
		t.Fatalf("second Listen() error = %v, want ErrAlreadyRunning", err)
	}
	connection, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("Dial(): %v", err)
	}
	if err := server.Close(); err != nil {
		t.Fatalf("Close(): %v", err)
	}
	_ = connection.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 1)
	if _, err := connection.Read(buffer); err == nil {
		t.Fatal("control connection remained open")
	}
	_ = connection.Close()
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("control socket remained: %v", err)
	}
}

func TestControlListenerDoesNotReplaceNonSocketOrInsecureDirectory(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "control")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatalf("Mkdir(): %v", err)
	}
	path := filepath.Join(directory, "daemon.sock")
	if err := os.WriteFile(path, []byte("preserve"), 0o600); err != nil {
		t.Fatalf("WriteFile(): %v", err)
	}
	if _, err := Listen(path, uint32(os.Geteuid()), &testHandler{}); err == nil {
		t.Fatal("Listen() replaced a non-socket path")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "preserve" {
		t.Fatalf("non-socket path changed: %q, %v", data, err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("Remove(): %v", err)
	}
	if err := os.Chmod(directory, 0o755); err != nil {
		t.Fatalf("Chmod(): %v", err)
	}
	if _, err := Listen(path, uint32(os.Geteuid()), &testHandler{}); err == nil {
		t.Fatal("Listen() accepted an insecure existing directory")
	}
	assertPermission(t, directory, 0o755)
}

func TestClientRejectsServerVersionMismatch(t *testing.T) {
	path := controlPath(t)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatalf("ListenUnix(): %v", err)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		connection, acceptErr := listener.AcceptUnix()
		if acceptErr != nil {
			return
		}
		defer connection.Close()
		var request Request
		_ = readJSONFrame(connection, MaximumRequestBytes, &request)
		_ = writeJSONFrame(connection, MaximumResponseBytes, Response{
			Version: Version + 1, OK: true, Error: ErrorNone,
			Status: &StatusResult{Daemon: HealthHealthy, Upstream: HealthHealthy, Consumers: []ConsumerStatus{}},
		})
	}()
	client, _ := NewClient(path)
	if _, err := client.Status(); err == nil || err.Error() != "daemon control protocol version mismatch" {
		t.Fatalf("Status() error = %v", err)
	}
	<-done
}

func controlPath(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	directory := filepath.Join(root, "control")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatalf("Mkdir(): %v", err)
	}
	return filepath.Join(directory, "daemon.sock")
}

func assertPermission(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat(%s): %v", path, err)
	}
	if info.Mode().Perm() != want {
		t.Fatalf("mode(%s) = %o, want %o", path, info.Mode().Perm(), want)
	}
}
