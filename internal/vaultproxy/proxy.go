// ---
// relationships:
//   implements: vault-socket-proxy
//   uses: make-openbao-the-secret-and-key-authority
// ---

// Package vaultproxy serves the OpenBao HTTP API on a container's vault
// socket. Every forwarded request carries the container's own token in
// place of whatever the client sent, and the real token never appears in a
// response.
package vaultproxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/wyrd-company/wyrwood/internal/binding"
	"github.com/wyrd-company/wyrwood/internal/events"
)

// DefaultMaximumRequestBytes bounds request bodies.
const DefaultMaximumRequestBytes = 1 << 20

const maximumScrubbedResponseBytes = 32 << 20

var (
	loginPath       = regexp.MustCompile(`^auth/[^/]+/login(/.*)?$`)
	tokenCreatePath = regexp.MustCompile(`^auth/token/create(-orphan)?(/.*)?$`)
	refusedPath     = regexp.MustCompile(`^auth/token/(revoke-self|revoke(/.*)?|revoke-accessor|revoke-orphan(/.*)?|renew(/.*)?|renew-accessor)$`)
)

var hopHeaders = []string{
	"Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Proxy-Connection",
	"Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

// Proxy serves vault sockets.
type Proxy struct {
	MaximumRequestBytes int64
	Timeout             time.Duration

	mu         sync.Mutex
	transports map[string]*http.Transport
	wrapped    map[string]map[string]time.Time
}

// New returns a proxy with default bounds.
func New(timeout time.Duration) *Proxy {
	return &Proxy{
		MaximumRequestBytes: DefaultMaximumRequestBytes, Timeout: timeout,
		transports: map[string]*http.Transport{}, wrapped: map[string]map[string]time.Time{},
	}
}

// Serve serves one consumer's vault socket until the listener closes.
func (proxy *Proxy) Serve(listener net.Listener, lookup binding.Lookup, record binding.Recorder) {
	server := &http.Server{
		Handler:           proxy.Handler(lookup, record),
		ReadHeaderTimeout: 30 * time.Second,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          nil,
	}
	_ = server.Serve(listener)
}

// Handler returns the HTTP handler for one consumer.
func (proxy *Proxy) Handler(lookup binding.Lookup, record binding.Recorder) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		proxy.serve(writer, request, lookup, record)
	})
}

type exchange struct {
	started time.Time
	view    binding.View
	mount   events.Mount
	method  events.Method
	record  binding.Recorder
}

func (exchange exchange) finish(outcome events.Outcome, code events.ErrorCode) {
	if exchange.record == nil {
		return
	}
	exchange.record(events.Event{
		Time: time.Now().UTC(), Operation: events.OperationVaultRequest, Outcome: outcome, ErrorCode: code,
		Latency: time.Since(exchange.started), Binding: exchange.view.ID, ContainerKey: exchange.view.ContainerKey,
		Mount: exchange.mount, Method: exchange.method,
	})
}

func (proxy *Proxy) serve(writer http.ResponseWriter, request *http.Request, lookup binding.Lookup, record binding.Recorder) {
	path := strings.TrimPrefix(request.URL.Path, "/v1/")
	current := exchange{started: time.Now(), method: method(request), record: record}
	view, bound := lookup()
	current.view = view
	current.mount = mountCategory(path, view.Mounts)
	if !strings.HasPrefix(request.URL.Path, "/v1/") || strings.Contains(path, "..") {
		writeErrors(writer, http.StatusNotFound, "unsupported path")
		current.finish(events.OutcomeFailed, events.ErrorProtocol)
		return
	}
	if !bound {
		writeUnavailable(writer, "not-bound", "this container is not bound to a Wyrwood policy")
		current.finish(events.OutcomeDenied, events.ErrorNotBound)
		return
	}
	if !view.HasToken {
		writeUnavailable(writer, "no-token", "the Wyrwood agent holds no OpenBao token for this container yet")
		current.finish(events.OutcomeFailed, events.ErrorNoToken)
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, proxy.MaximumRequestBytes)
	placeholder := Placeholder(view.ID)
	switch {
	case (request.Method == http.MethodPost || request.Method == http.MethodPut) && (loginPath.MatchString(path) || tokenCreatePath.MatchString(path)):
		_, _ = io.Copy(io.Discard, request.Body)
		writeJSON(writer, http.StatusOK, syntheticAuth(view, placeholder))
		current.finish(events.OutcomeOK, events.ErrorNone)
		return
	case path == "auth/token/renew-self" && (request.Method == http.MethodPost || request.Method == http.MethodPut):
		_, _ = io.Copy(io.Discard, request.Body)
		proxy.renewSelf(writer, request, view, placeholder, current)
		return
	case refusedPath.MatchString(path):
		writeErrors(writer, http.StatusForbidden, "permission denied")
		current.finish(events.OutcomeDenied, events.ErrorPolicyDenied)
		return
	case path == "sys/wrapping/unwrap":
		body, err := io.ReadAll(request.Body)
		if err != nil {
			writeErrors(writer, http.StatusRequestEntityTooLarge, "request body too large")
			current.finish(events.OutcomeFailed, events.ErrorProtocol)
			return
		}
		var unwrap struct {
			Token string `json:"token"`
		}
		_ = json.Unmarshal(body, &unwrap)
		if unwrap.Token == "" || !proxy.consumeWrapped(view.ID, unwrap.Token) {
			writeErrors(writer, http.StatusForbidden, "permission denied")
			current.finish(events.OutcomeDenied, events.ErrorPolicyDenied)
			return
		}
		request.Body = io.NopCloser(bytes.NewReader(body))
		request.ContentLength = int64(len(body))
	}
	proxy.forward(writer, request, view, placeholder, current)
}

func method(request *http.Request) events.Method {
	switch request.Method {
	case http.MethodGet, http.MethodHead:
		if request.URL.Query().Get("list") == "true" {
			return events.MethodList
		}
		return events.MethodGet
	case "LIST":
		return events.MethodList
	case http.MethodPost:
		return events.MethodPost
	case http.MethodPut, http.MethodPatch:
		return events.MethodPut
	case http.MethodDelete:
		return events.MethodDelete
	}
	return events.MethodNone
}

func mountCategory(path string, mounts binding.Mounts) events.Mount {
	first, _, _ := strings.Cut(path, "/")
	switch {
	case first == "":
		return events.MountOther
	case first == "sys":
		return events.MountSys
	case first == "auth":
		return events.MountAuth
	case first == mounts.Transit:
		return events.MountTransit
	case first == mounts.SSH:
		return events.MountSSH
	case first == "secret" || strings.HasPrefix(first, "kv"):
		return events.MountKV
	}
	return events.MountOther
}

// Placeholder is the opaque client token the proxy hands out for a binding.
func Placeholder(bindingID string) string {
	sum := sha256.Sum256([]byte("wyrwood-placeholder:" + bindingID))
	return "wyrwood." + hex.EncodeToString(sum[:12])
}

func syntheticAuth(view binding.View, placeholder string) map[string]any {
	policies := view.Token.Policies
	if policies == nil {
		policies = []string{}
	}
	ttl := 0
	if expires := view.Token.Expires(); !expires.IsZero() {
		ttl = int(time.Until(expires) / time.Second)
	}
	return map[string]any{
		"request_id": requestID(), "lease_id": "", "renewable": false, "lease_duration": 0,
		"data": nil, "wrap_info": nil, "warnings": nil, "mount_type": "",
		"auth": map[string]any{
			"client_token": placeholder, "accessor": "", "policies": policies, "token_policies": policies,
			"identity_policies": nil, "metadata": map[string]string{"wyrwood": "agent-held"},
			"lease_duration": ttl, "renewable": true, "entity_id": "", "token_type": "service", "orphan": true,
			"mfa_requirement": nil, "num_uses": 0,
		},
	}
}

func requestID() string {
	var data [16]byte
	_, _ = rand.Read(data[:])
	encoded := hex.EncodeToString(data[:])
	return encoded[0:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:]
}

// renewSelf answers a renewal with the forwarded lookup, because the agent
// owns renewal.
func (proxy *Proxy) renewSelf(writer http.ResponseWriter, request *http.Request, view binding.View, placeholder string, current exchange) {
	lookup := request.Clone(request.Context())
	lookup.Method = http.MethodGet
	lookup.URL = &url.URL{Path: "/v1/auth/token/lookup-self"}
	lookup.Body = http.NoBody
	lookup.ContentLength = 0
	response, err := proxy.roundTrip(lookup, view)
	if err != nil {
		writeErrors(writer, http.StatusBadGateway, "OpenBao unavailable")
		current.finish(timeoutOutcome(err))
		return
	}
	defer response.Body.Close()
	var looked struct {
		Data struct {
			Accessor  string   `json:"accessor"`
			Policies  []string `json:"policies"`
			TTL       int      `json:"ttl"`
			Renewable bool     `json:"renewable"`
		} `json:"data"`
	}
	if response.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&looked) != nil {
		writeErrors(writer, http.StatusForbidden, "permission denied")
		current.finish(events.OutcomeDenied, events.ErrorOpenBaoDenied)
		return
	}
	synthetic := syntheticAuth(view, placeholder)
	auth := synthetic["auth"].(map[string]any)
	auth["accessor"] = looked.Data.Accessor
	auth["policies"] = looked.Data.Policies
	auth["token_policies"] = looked.Data.Policies
	auth["lease_duration"] = looked.Data.TTL
	auth["renewable"] = looked.Data.Renewable
	writeJSON(writer, http.StatusOK, synthetic)
	current.finish(events.OutcomeOK, events.ErrorNone)
}

func (proxy *Proxy) forward(writer http.ResponseWriter, request *http.Request, view binding.View, placeholder string, current exchange) {
	response, err := proxy.roundTrip(request, view)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeErrors(writer, http.StatusRequestEntityTooLarge, "request body too large")
			current.finish(events.OutcomeFailed, events.ErrorProtocol)
			return
		}
		writeErrors(writer, http.StatusBadGateway, "OpenBao unavailable")
		current.finish(timeoutOutcome(err))
		return
	}
	defer response.Body.Close()
	header := writer.Header()
	for name, values := range response.Header {
		header[name] = values
	}
	for _, name := range hopHeaders {
		header.Del(name)
	}
	token := []byte(view.Token.Value())
	if strings.HasPrefix(response.Header.Get("Content-Type"), "application/json") && response.ContentLength <= maximumScrubbedResponseBytes {
		body, err := io.ReadAll(io.LimitReader(response.Body, maximumScrubbedResponseBytes+1))
		if err != nil || len(body) > maximumScrubbedResponseBytes {
			writeErrors(writer, http.StatusBadGateway, "OpenBao response too large")
			current.finish(events.OutcomeFailed, events.ErrorOpenBaoUnavailable)
			return
		}
		body = bytes.ReplaceAll(body, token, []byte(placeholder))
		proxy.rememberWrapped(view.ID, body)
		header.Del("Content-Length")
		writer.WriteHeader(response.StatusCode)
		_, _ = writer.Write(body)
	} else {
		writer.WriteHeader(response.StatusCode)
		flusher, _ := writer.(http.Flusher)
		buffer := make([]byte, 32<<10)
		for {
			count, readErr := response.Body.Read(buffer)
			if count > 0 {
				if _, err := writer.Write(buffer[:count]); err != nil {
					break
				}
				if flusher != nil {
					flusher.Flush()
				}
			}
			if readErr != nil {
				break
			}
		}
	}
	current.finish(statusOutcome(response.StatusCode))
}

func (proxy *Proxy) roundTrip(request *http.Request, view binding.View) (*http.Response, error) {
	base, err := url.Parse(view.OpenBao.Address)
	if err != nil {
		return nil, err
	}
	target := *base
	target.Path = strings.TrimRight(base.Path, "/") + request.URL.Path
	target.RawQuery = request.URL.RawQuery
	// The transport's response-header timeout bounds OpenBao; bodies,
	// including streaming responses, are bounded by the client connection.
	upstream, err := http.NewRequestWithContext(request.Context(), request.Method, target.String(), request.Body)
	if err != nil {
		return nil, err
	}
	upstream.ContentLength = request.ContentLength
	for name, values := range request.Header {
		upstream.Header[name] = append([]string(nil), values...)
	}
	for _, name := range hopHeaders {
		upstream.Header.Del(name)
	}
	upstream.Header.Del("Authorization")
	upstream.Header.Del("X-Vault-Token")
	upstream.Header.Del("X-Vault-Namespace")
	upstream.Header.Set("X-Vault-Token", view.Token.Value())
	if view.OpenBao.Namespace != "" {
		upstream.Header.Set("X-Vault-Namespace", view.OpenBao.Namespace)
	}
	transport, err := proxy.transport(view)
	if err != nil {
		return nil, err
	}
	response, err := transport.RoundTrip(upstream)
	return response, err
}

func (proxy *Proxy) transport(view binding.View) (*http.Transport, error) {
	key := view.OpenBao.Address + "\x00" + view.OpenBao.CAPEM
	proxy.mu.Lock()
	defer proxy.mu.Unlock()
	if transport, ok := proxy.transports[key]; ok {
		return transport, nil
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if view.OpenBao.CAPEM != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(view.OpenBao.CAPEM)) {
			return nil, errors.New("invalid OpenBao CA")
		}
		tlsConfig.RootCAs = pool
	}
	transport := &http.Transport{
		Proxy: nil, TLSClientConfig: tlsConfig, MaxIdleConnsPerHost: 8, IdleConnTimeout: 90 * time.Second,
		ResponseHeaderTimeout: proxy.Timeout, ForceAttemptHTTP2: true,
		DialContext: (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
	}
	proxy.transports[key] = transport
	return transport, nil
}

// rememberWrapped records response-wrapping tokens the container created so
// it may unwrap them later.
func (proxy *Proxy) rememberWrapped(bindingID string, body []byte) {
	if !bytes.Contains(body, []byte(`"wrap_info"`)) {
		return
	}
	var response struct {
		WrapInfo *struct {
			Token string `json:"token"`
			TTL   int    `json:"ttl"`
		} `json:"wrap_info"`
	}
	if json.Unmarshal(body, &response) != nil || response.WrapInfo == nil || response.WrapInfo.Token == "" {
		return
	}
	proxy.mu.Lock()
	defer proxy.mu.Unlock()
	tokens := proxy.wrapped[bindingID]
	if tokens == nil {
		tokens = map[string]time.Time{}
		proxy.wrapped[bindingID] = tokens
	}
	now := time.Now()
	for token, expires := range tokens {
		if now.After(expires) {
			delete(tokens, token)
		}
	}
	if len(tokens) < 1024 {
		tokens[response.WrapInfo.Token] = now.Add(time.Duration(response.WrapInfo.TTL) * time.Second)
	}
}

func (proxy *Proxy) consumeWrapped(bindingID, token string) bool {
	proxy.mu.Lock()
	defer proxy.mu.Unlock()
	expires, ok := proxy.wrapped[bindingID][token]
	if !ok || time.Now().After(expires) {
		return false
	}
	delete(proxy.wrapped[bindingID], token)
	return true
}

func timeoutOutcome(err error) (events.Outcome, events.ErrorCode) {
	var netErr net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()) {
		return events.OutcomeTimeout, events.ErrorOpenBaoTimeout
	}
	return events.OutcomeFailed, events.ErrorOpenBaoUnavailable
}

func statusOutcome(status int) (events.Outcome, events.ErrorCode) {
	switch {
	case status < 400:
		return events.OutcomeOK, events.ErrorNone
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return events.OutcomeDenied, events.ErrorOpenBaoDenied
	case status >= 500:
		return events.OutcomeFailed, events.ErrorOpenBaoUnavailable
	default:
		return events.OutcomeFailed, events.ErrorProtocol
	}
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func writeErrors(writer http.ResponseWriter, status int, message string) {
	writeJSON(writer, status, map[string]any{"errors": []string{message}})
}

// writeUnavailable answers with a categorical 503 whose body lets a tool
// tell an unbound or controller-absent state from an OpenBao denial.
func writeUnavailable(writer http.ResponseWriter, state, message string) {
	writeJSON(writer, http.StatusServiceUnavailable, map[string]any{
		"errors":  []string{"wyrwood: " + message},
		"wyrwood": map[string]string{"state": state},
	})
}
