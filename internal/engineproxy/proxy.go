// ---
// relationships:
//   implements: engine-proxy
// ---

package engineproxy

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync"
)

// Proxy holds a fixed host permission and a Unix-only Engine transport.
type Proxy struct {
	handler   *httputil.ReverseProxy
	recreate  bool
	log       io.Writer
	logMu     sync.Mutex
	transport *http.Transport
}

// New never consults a request destination, environment proxy, or DNS.
func New(socket string, recreate bool, output io.Writer) *Proxy {
	if output == nil {
		output = io.Discard
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}
	proxy := &Proxy{recreate: recreate, log: output, transport: transport}
	proxy.handler = &httputil.ReverseProxy{
		Transport: transport,
		Rewrite: func(request *httputil.ProxyRequest) {
			request.Out.URL.Scheme = "http"
			request.Out.URL.Host = "engine"
			request.Out.Host = "engine"
			for _, header := range []string{"Authorization", "Proxy-Authorization", "X-Registry-Auth", "Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "Idempotency-Key", "X-Idempotency-Key"} {
				request.Out.Header.Del(header)
			}
		},
		ErrorLog:     log.New(io.Discard, "", 0),
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, _ error) { categorical(w, http.StatusBadGateway) },
		// Event records must be visible while the Engine keeps the response open.
		FlushInterval: -1,
	}
	return proxy
}

func (proxy *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	operation, status := authorize(r, proxy.recreate)
	if status != 0 {
		reject(w, r, status)
		proxy.record(operation, status)
		return
	}
	response := &responseState{ResponseWriter: w, status: http.StatusOK}
	proxy.handler.ServeHTTP(response, r)
	// Never log a request URI, body, or upstream error, even on denial.
	proxy.record(operation, response.status)
}

func (proxy *Proxy) record(operation string, status int) {
	proxy.logMu.Lock()
	defer proxy.logMu.Unlock()
	_, _ = fmt.Fprintf(proxy.log, "engine-proxy operation=%s outcome=%d\n", operation, status/100)
}

// Close releases cached upstream connections; active requests are owned by Serve.
func (proxy *Proxy) Close() { proxy.transport.CloseIdleConnections() }

func categorical(w http.ResponseWriter, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, `{"message":"engine proxy request unavailable"}`+"\n")
}

// Serve closes active requests, including event streams, immediately on stop.
func (proxy *Proxy) Serve(ctx context.Context, listener net.Listener) error {
	defer listener.Close()
	defer proxy.Close()
	server := &http.Server{Handler: proxy, ErrorLog: log.New(io.Discard, "", 0), DisableGeneralOptionsHandler: true}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = server.Close()
		case <-done:
		}
	}()
	defer close(done)
	err := server.Serve(listener)
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

// Unwrap lets ResponseController preserve streaming through the status recorder.
type responseState struct {
	http.ResponseWriter
	status int
}

func (state *responseState) WriteHeader(status int) {
	state.status = status
	state.ResponseWriter.WriteHeader(status)
}
func (state *responseState) Unwrap() http.ResponseWriter { return state.ResponseWriter }

// A denied body is never drained for keep-alive reuse. In particular, a caller
// need not upload a create payload before learning that host writes are denied.
func reject(w http.ResponseWriter, r *http.Request, status int) {
	if r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
		connection, buffer, err := http.NewResponseController(w).Hijack()
		if err == nil {
			defer connection.Close()
			body := `{"message":"engine proxy request unavailable"}` + "\n"
			response := &http.Response{StatusCode: status, ProtoMajor: 1, ProtoMinor: 1, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body)), Close: true}
			_ = response.Write(buffer)
			_ = buffer.Flush()
			return
		}
	}
	categorical(w, status)
}
