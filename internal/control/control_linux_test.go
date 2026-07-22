//go:build linux

// ---
// relationships:
//   verifies: control-interface
// ---

package control

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
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
	credentialChecked := make(chan struct{})
	server, err := listenWithPeerCredential(path, uint32(os.Geteuid()), handler, func(*net.UnixConn) (uint32, error) {
		close(credentialChecked)
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
	<-credentialChecked
	if err := writeJSONFrame(connection, MaximumRequestBytes, Request{Version: Version, Operation: OperationStatus}); err == nil {
		var response Response
		if err := readJSONFrame(connection, MaximumResponseBytes, &response); err == nil {
			t.Fatalf("unauthorized peer received response %#v", response)
		}
	}
	if handler.calls.Load() != 0 {
		t.Fatalf("unauthorized peer reached handler %d times", handler.calls.Load())
	}
}

func TestWriteResponseNeverAppendsFallbackAfterPartialWrite(t *testing.T) {
	response := Response{
		Version: Version, OK: true, Error: ErrorNone,
		Status: &StatusResult{Daemon: HealthHealthy, Upstream: HealthUnavailable, Consumers: []ConsumerStatus{}},
	}
	full, err := encodeJSONFrame(MaximumResponseBytes, response)
	if err != nil {
		t.Fatalf("encodeJSONFrame(): %v", err)
	}
	writer := &failAfterWriter{remaining: 7}
	if err := writeResponse(writer, response); err == nil {
		t.Fatal("writeResponse() error = nil")
	}
	if !bytes.Equal(writer.Bytes(), full[:7]) {
		t.Fatalf("partial response = %x, want only primary prefix %x", writer.Bytes(), full[:7])
	}
}

func TestWriteResponsePreEncodesResourceLimitWithoutPrimaryBytes(t *testing.T) {
	response := Response{
		Version: Version, OK: true, Error: ErrorNone,
		Status: &StatusResult{
			Daemon: HealthHealthy, Upstream: HealthHealthy,
			Consumers: []ConsumerStatus{{ID: "subject", Name: strings.Repeat("x", MaximumResponseBytes), Listener: HealthHealthy}},
		},
	}
	var encoded bytes.Buffer
	if err := writeResponse(&encoded, response); err != nil {
		t.Fatalf("writeResponse(): %v", err)
	}
	var projected Response
	if err := readJSONFrame(&encoded, MaximumResponseBytes, &projected); err != nil {
		t.Fatalf("readJSONFrame(): %v", err)
	}
	if projected.OK || projected.Error != ErrorResourceLimit || projected.Status != nil {
		t.Fatalf("projected response = %#v", projected)
	}
}

func TestMaximumStatusProjectionFitsTheResponseFrame(t *testing.T) {
	consumers := make([]ConsumerStatus, MaximumProjectedConsumers)
	for index := range consumers {
		consumers[index] = ConsumerStatus{
			ID: strings.Repeat("i", 128), Name: strings.Repeat("\u2028", MaximumConsumerNameCharacters),
			Listener: HealthHealthy,
		}
	}
	response := Response{
		Version: Version, OK: true, Error: ErrorNone,
		Status: &StatusResult{Daemon: HealthHealthy, Upstream: HealthHealthy, Consumers: consumers},
	}
	frame, err := encodeJSONFrame(MaximumResponseBytes, response)
	if err != nil {
		t.Fatalf("maximum status projection does not fit: %v", err)
	}
	if len(frame) > MaximumResponseBytes+4 {
		t.Fatalf("maximum status frame = %d bytes", len(frame))
	}
}

type failAfterWriter struct {
	bytes.Buffer
	remaining int
}

func (writer *failAfterWriter) Write(data []byte) (int, error) {
	if writer.remaining <= 0 {
		return 0, errors.New("injected write failure")
	}
	length := min(writer.remaining, len(data))
	writer.remaining -= length
	_, _ = writer.Buffer.Write(data[:length])
	if length < len(data) {
		return length, errors.New("injected write failure")
	}
	return length, nil
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

func TestClientBoundsTheCompleteControlExchange(t *testing.T) {
	path := controlPath(t)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatalf("ListenUnix(): %v", err)
	}
	defer listener.Close()
	release := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		connection, acceptErr := listener.AcceptUnix()
		if acceptErr != nil {
			return
		}
		defer connection.Close()
		<-release
	}()

	client, err := NewClient(path)
	if err != nil {
		t.Fatalf("NewClient(): %v", err)
	}
	client.timeout = 20 * time.Millisecond
	started := time.Now()
	_, requestErr := client.Status()
	elapsed := time.Since(started)
	close(release)
	<-done
	if requestErr == nil {
		t.Fatal("Status() error = nil")
	}
	if elapsed > 250*time.Millisecond {
		t.Fatalf("Status() elapsed = %s, want bounded by one client deadline", elapsed)
	}
}

func TestClientRejectsInvalidSuccessProjections(t *testing.T) {
	timestamp := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	tests := []struct {
		name     string
		request  Request
		response Response
	}{
		{
			name: "negative apply count", request: Request{Version: Version, Operation: OperationApply},
			response: Response{Version: Version, OK: true, Error: ErrorNone, Apply: &ApplyResult{Committed: true, PendingCleanup: -1}},
		},
		{
			name: "invalid key fingerprint", request: Request{Version: Version, Operation: OperationKeys},
			response: Response{Version: Version, OK: true, Error: ErrorNone, Keys: &KeysResult{Keys: []Key{{Fingerprint: "invalid"}}}},
		},
		{
			name: "null key list", request: Request{Version: Version, Operation: OperationKeys},
			response: Response{Version: Version, OK: true, Error: ErrorNone, Keys: &KeysResult{}},
		},
		{
			name: "oversized key display", request: Request{Version: Version, Operation: OperationKeys},
			response: Response{Version: Version, OK: true, Error: ErrorNone, Keys: &KeysResult{Keys: []Key{{Fingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", Display: strings.Repeat("x", MaximumDisplayBytes+1)}}}},
		},
		{
			name: "oversized consumer ID", request: Request{Version: Version, Operation: OperationStatus},
			response: Response{Version: Version, OK: true, Error: ErrorNone, Status: &StatusResult{Daemon: HealthHealthy, Upstream: HealthHealthy, Consumers: []ConsumerStatus{{ID: strings.Repeat("x", 129), Name: "sample", Listener: HealthHealthy}}}},
		},
		{
			name: "null consumer list", request: Request{Version: Version, Operation: OperationStatus},
			response: Response{Version: Version, OK: true, Error: ErrorNone, Status: &StatusResult{Daemon: HealthHealthy, Upstream: HealthHealthy}},
		},
		{
			name: "invalid event category", request: Request{Version: Version, Operation: OperationEvents, Limit: pointerTo(1)},
			response: Response{Version: Version, OK: true, Error: ErrorNone, Events: &EventsResult{Events: []Event{{Timestamp: timestamp, ConsumerID: "unit", Operation: "unknown", Outcome: "failed", ErrorCode: "internal"}}}},
		},
		{
			name: "null event list", request: Request{Version: Version, Operation: OperationEvents, Limit: pointerTo(1)},
			response: Response{Version: Version, OK: true, Error: ErrorNone, Events: &EventsResult{}},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := validateResponse(test.request, test.response); err == nil {
				t.Fatalf("validateResponse(%#v) error = nil", test.response)
			}
		})
	}
}

func pointerTo(value int) *int { return &value }

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
