// ---
// relationships:
//   verifies: engine-proxy
// ---

package engineproxy

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wyrd-company/wyrwood/internal/engine"
)

func unixUpstream(t *testing.T, handler http.Handler) string {
	t.Helper()
	socket := filepath.Join(t.TempDir(), "upstream.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: handler}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	return socket
}

func TestForwardingUsesOnlyConfiguredSocketAndRedacts(t *testing.T) {
	var calls atomic.Int32
	socket := unixUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Host != "engine" || r.URL.Path != "/images/registry.example/sample:tag/json" {
			t.Errorf("wrong target %s %s", r.Host, r.URL.Path)
		}
		if r.RequestURI != "/images/registry.example%2Fsample:tag/json" {
			t.Errorf("image reference changed on wire: %s", r.RequestURI)
		}
		for _, key := range []string{"Authorization", "X-Registry-Auth", "Forwarded", "X-Forwarded-For", "Idempotency-Key", "X-Idempotency-Key"} {
			if _, ok := r.Header[key]; ok {
				t.Errorf("forwarded %s", key)
			}
		}
		_, _ = io.WriteString(w, `{"Id":"sample"}`)
	}))
	var logs bytes.Buffer
	proxy := New(socket, false, &logs)
	defer proxy.Close()
	r := httptest.NewRequest("GET", "/images/registry.example%2Fsample%3Atag/json", nil)
	for _, key := range []string{"Authorization", "X-Registry-Auth", "Forwarded", "X-Forwarded-For", "Idempotency-Key", "X-Idempotency-Key"} {
		r.Header.Set(key, "sensitive-marker")
	}
	result := httptest.NewRecorder()
	proxy.ServeHTTP(result, r)
	if result.Code != 200 || calls.Load() != 1 {
		t.Fatalf("forwarded = %d calls %d", result.Code, calls.Load())
	}
	result = httptest.NewRecorder()
	proxy.ServeHTTP(result, httptest.NewRequest("GET", "/containers/sample/archive?path=sensitive-marker", nil))
	if result.Code != 403 || calls.Load() != 1 {
		t.Fatal("denied request reached Engine")
	}
	if strings.Contains(logs.String(), "sensitive-marker") || strings.Contains(logs.String(), "registry.example") {
		t.Fatalf("logs expose URI: %s", logs.String())
	}
}

func TestCreatePermissionIsCheckedBeforeReadingBody(t *testing.T) {
	body := &panicReader{}
	request := httptest.NewRequest("POST", "/containers/create?name=sample", nil)
	request.Body = body
	request.ContentLength = -1
	request.Header.Set("Content-Type", "application/json")
	proxy := New("/missing.sock", false, nil)
	defer proxy.Close()
	result := httptest.NewRecorder()
	proxy.ServeHTTP(result, request)
	if result.Code != 403 {
		t.Fatalf("disabled create = %d", result.Code)
	}
}

type panicReader struct{}

func (*panicReader) Read([]byte) (int, error) { panic("denied create body read") }
func (*panicReader) Close() error             { return nil }

func TestCreateBodyAndEngineStatusArePreserved(t *testing.T) {
	payload := `{"Image":"sample","HostConfig":{"Privileged":true,"Binds":["/:/host"]}}`
	socket := unixUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		if string(data) != payload || r.URL.Query().Get("name") != "sample" {
			t.Error("create changed")
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"Id":"new-id"}`)
	}))
	proxy := New(socket, true, nil)
	defer proxy.Close()
	request := httptest.NewRequest("POST", "/containers/create?name=sample", strings.NewReader(payload))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	proxy.ServeHTTP(response, request)
	if response.Code != 201 || !strings.Contains(response.Body.String(), "new-id") {
		t.Fatal(response.Code, response.Body.String())
	}
}

func TestStreamingCancellationAndCategoricalTransportFailure(t *testing.T) {
	upstreamCanceled := make(chan struct{})
	socket := unixUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"Action":"create","Actor":{"ID":"sample"}}`+"\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		close(upstreamCanceled)
	}))
	proxy := New(socket, false, nil)
	filtered := filepath.Join(t.TempDir(), "filtered.sock")
	listener, err := net.Listen("unix", filtered)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := make(chan error, 1)
	go func() { finished <- proxy.Serve(ctx, listener) }()
	events, failure := engine.NewClient(filtered).Events(ctx)
	select {
	case event := <-events:
		if event.ID != "sample" {
			t.Fatal(event)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("buffered event stream")
	}
	cancel()
	select {
	case <-upstreamCanceled:
	case <-time.After(5 * time.Second):
		t.Fatal("upstream not canceled")
	}
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	<-failure
	broken := New(filepath.Join(t.TempDir(), "private-marker.sock"), false, nil)
	defer broken.Close()
	response := httptest.NewRecorder()
	broken.ServeHTTP(response, httptest.NewRequest("GET", "/containers/json?all=1", nil))
	if response.Code != 502 || strings.Contains(response.Body.String(), "private-marker") {
		t.Fatal(response.Code, response.Body.String())
	}
}

func TestKeepAlivePermissionAndHTTPFraming(t *testing.T) {
	var calls atomic.Int32
	socket := unixUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); _, _ = io.WriteString(w, "[]") }))
	proxy := New(socket, false, nil)
	server := httptest.NewServer(proxy)
	defer server.Close()
	defer proxy.Close()
	conn, err := net.Dial("tcp", strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	reader := bufio.NewReader(conn)
	for _, sample := range []struct {
		request string
		status  int
	}{
		{"GET /containers/json?all=1 HTTP/1.1\r\nHost: local\r\n\r\n", 200},
		{"POST /containers/sample/start HTTP/1.1\r\nHost: local\r\nContent-Length: 0\r\n\r\n", 403},
		{"GET /containers/json?all=1 HTTP/1.1\r\nHost: local\r\nContent-Length: 0\r\nContent-Length: 2\r\n\r\n", 400},
	} {
		_, _ = io.WriteString(conn, sample.request)
		response, err := http.ReadResponse(reader, nil)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
		if response.StatusCode != sample.status {
			t.Fatalf("response = %d, want %d", response.StatusCode, sample.status)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("denied request forwarded: %d", calls.Load())
	}
}

func TestDeniedCreateReturnsBeforeBodyUpload(t *testing.T) {
	proxy := New("/missing.sock", false, nil)
	server := httptest.NewServer(proxy)
	defer server.Close()
	defer proxy.Close()
	conn, err := net.Dial("tcp", strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	// Deliberately omit the body. net/http normally drains small unread bodies
	// before writing a response; denial must bypass that behavior.
	_, _ = io.WriteString(conn, "POST /containers/create?name=sample HTTP/1.1\r\nHost: local\r\nContent-Type: application/json\r\nContent-Length: 10\r\n\r\n")
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal("denied create waited for body upload", err)
	}
	defer response.Body.Close()
	if response.StatusCode != 403 {
		t.Fatal(response.StatusCode)
	}
}

func TestEngineClientOperationsCrossOnlyApprovedRoutes(t *testing.T) {
	for _, permission := range []bool{false, true} {
		t.Run(map[bool]string{false: "reads", true: "recreate"}[permission], func(t *testing.T) {
			var writes atomic.Int32
			socket := unixUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" {
					writes.Add(1)
				}
				switch {
				case r.URL.Path == "/containers/json":
					_, _ = io.WriteString(w, `[{"Id":"sample"}]`)
				case r.URL.Path == "/containers/sample/json":
					_, _ = io.WriteString(w, `{"Id":"sample","Name":"/sample"}`)
				case strings.HasPrefix(r.URL.Path, "/images/"):
					_, _ = io.WriteString(w, `{"Id":"sha256:sample"}`)
				case r.URL.Path == "/events":
					_, _ = io.WriteString(w, `{"Action":"create","Actor":{"ID":"sample"}}`+"\n")
				case r.URL.Path == "/containers/create":
					w.WriteHeader(201)
					_, _ = io.WriteString(w, `{"Id":"new-sample"}`)
				default:
					w.WriteHeader(204)
				}
			}))
			filtered := filepath.Join(t.TempDir(), "filtered.sock")
			listener, err := net.Listen("unix", filtered)
			if err != nil {
				t.Fatal(err)
			}
			proxy := New(socket, permission, nil)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			done := make(chan error, 1)
			go func() { done <- proxy.Serve(ctx, listener) }()
			defer func() {
				cancel()
				if err := <-done; err != nil {
					t.Error(err)
				}
			}()
			client := engine.NewClient(filtered)
			if _, err := client.List(ctx); err != nil {
				t.Fatal(err)
			}
			if _, err := client.Inspect(ctx, "sample"); err != nil {
				t.Fatal(err)
			}
			if id, err := client.ImageID(ctx, "registry.example/sample:tag"); err != nil || id != "sha256:sample" {
				t.Fatal(id, err)
			}
			stream, _ := client.Events(ctx)
			select {
			case event := <-stream:
				if event.ID != "sample" {
					t.Fatal(event)
				}
			case <-ctx.Done():
				t.Fatal("event missing")
			}
			check := func(err error) {
				t.Helper()
				if permission && err != nil {
					t.Fatal(err)
				}
				if !permission && err != engine.ErrUnavailable {
					t.Fatal("write bypassed permission", err)
				}
			}
			check(client.Stop(ctx, "sample", time.Second))
			check(client.Remove(ctx, "sample"))
			_, err = client.Create(ctx, "sample", []byte(`{"Image":"sample"}`))
			check(err)
			check(client.Start(ctx, "new-sample"))
			want := int32(0)
			if permission {
				want = 4
			}
			if writes.Load() != want {
				t.Fatalf("forwarded writes = %d, want %d", writes.Load(), want)
			}
		})
	}
}
