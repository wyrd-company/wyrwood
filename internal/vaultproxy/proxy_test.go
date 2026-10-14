// ---
// relationships:
//   verifies: vault-socket-proxy
// ---

package vaultproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openbao/openbao/api/v2"

	"github.com/wyrd-company/wyrwood/internal/binding"
	"github.com/wyrd-company/wyrwood/internal/events"
	"github.com/wyrd-company/wyrwood/internal/openbao"
	"github.com/wyrd-company/wyrwood/internal/openbao/baotest"
	"github.com/wyrd-company/wyrwood/internal/policy"
	"github.com/wyrd-company/wyrwood/internal/protocol"
)

type recorder struct {
	mu     sync.Mutex
	events []events.Event
}

func (recorder *recorder) record(event events.Event) {
	if err := event.Validate(); err != nil {
		panic(err)
	}
	recorder.mu.Lock()
	recorder.events = append(recorder.events, event)
	recorder.mu.Unlock()
}

func (recorder *recorder) last() events.Event {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	return recorder.events[len(recorder.events)-1]
}

type fixture struct {
	socket   string
	view     binding.View
	mu       sync.Mutex
	bound    bool
	recorder *recorder
}

func (fixture *fixture) lookup() (binding.View, bool) {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	return fixture.view, fixture.bound
}

func (fixture *fixture) set(update func(*binding.View, *bool)) {
	fixture.mu.Lock()
	update(&fixture.view, &fixture.bound)
	fixture.mu.Unlock()
}

func serveFixture(t *testing.T, view binding.View) *fixture {
	t.Helper()
	fixture := &fixture{socket: filepath.Join(t.TempDir(), "vault.sock"), view: view, bound: true, recorder: &recorder{}}
	listener, err := net.Listen("unix", fixture.socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go New(5*time.Second).Serve(listener, fixture.lookup, fixture.recorder.record)
	return fixture
}

func containerClient(t *testing.T, socket string) *api.Client {
	t.Helper()
	configuration := api.DefaultConfig()
	configuration.Address = "unix://" + socket
	client, err := api.NewClient(configuration)
	if err != nil {
		t.Fatal(err)
	}
	client.ClearToken()
	return client
}

func bindingToken(t *testing.T, bao *baotest.Server, hcl string) openbao.Token {
	t.Helper()
	if err := bao.Root.Sys().PutPolicy("wyrwood-teal", hcl); err != nil {
		t.Fatal(err)
	}
	secret, err := bao.Root.Auth().Token().Create(&api.TokenCreateRequest{Policies: []string{"wyrwood-teal"}, TTL: "1h"})
	if err != nil {
		t.Fatal(err)
	}
	return openbao.NewToken(secret.Auth.ClientToken, time.Hour, secret.Auth.Policies...)
}

func TestProxyAgainstOpenBao(t *testing.T) {
	bao := baotest.Start(t)
	bao.WriteKV(t, "teams/teal/example", map[string]any{"value": "teal-secret"})
	bao.CreateTransitKey(t, "teal-aes", "aes256-gcm96")
	token := bindingToken(t, bao, `
path "kv/data/teams/teal/*" { capabilities = ["read"] }
path "transit/encrypt/teal-aes" { capabilities = ["update"] }
path "sys/wrapping/wrap" { capabilities = ["update"] }
`)
	view := binding.View{ID: "b-1", ContainerKey: "name:web", Policy: policy.New("teal", ""), OpenBao: protocol.OpenBao{Address: bao.Address},
		Mounts: binding.Mounts{Transit: "transit", SSH: "ssh"}, Token: token, HasToken: true}
	fixture := serveFixture(t, view)
	client := containerClient(t, fixture.socket)
	ctx := context.Background()

	client.SetToken("client-supplied-token")
	secret, err := client.KVv2("kv").Get(ctx, "teams/teal/example")
	if err != nil || secret.Data["value"] != "teal-secret" {
		t.Fatalf("KV read through proxy = %v, %v", secret, err)
	}
	if event := fixture.recorder.last(); event.Mount != events.MountKV || event.Method != events.MethodGet || event.Outcome != events.OutcomeOK {
		t.Fatalf("event = %#v", event)
	}
	if _, err := client.KVv2("kv").Get(ctx, "teams/other/example"); err == nil {
		t.Fatal("read outside policy succeeded")
	}
	if event := fixture.recorder.last(); event.Outcome != events.OutcomeDenied || event.ErrorCode != events.ErrorOpenBaoDenied {
		t.Fatalf("denied event = %#v", event)
	}

	client.ClearToken()
	login, err := client.Logical().Write("auth/approle/login", map[string]any{"role_id": "x", "secret_id": "y"})
	if err != nil || login.Auth == nil || login.Auth.ClientToken != Placeholder("b-1") || login.Auth.ClientToken == token.Value() {
		t.Fatalf("synthetic login = %#v, %v", login, err)
	}
	client.SetToken(login.Auth.ClientToken)
	if _, err := client.KVv2("kv").Get(ctx, "teams/teal/example"); err != nil {
		t.Fatalf("read after synthetic login = %v", err)
	}
	created, err := client.Auth().Token().Create(&api.TokenCreateRequest{})
	if err != nil || created.Auth.ClientToken != Placeholder("b-1") {
		t.Fatalf("synthetic token create = %#v, %v", created, err)
	}

	lookup, err := client.Auth().Token().LookupSelf()
	if err != nil {
		t.Fatalf("lookup-self = %v", err)
	}
	if encoded, _ := json.Marshal(lookup); bytes.Contains(encoded, []byte(token.Value())) {
		t.Fatal("lookup-self revealed the real token")
	}
	renewed, err := client.Auth().Token().RenewSelf(0)
	if err != nil || renewed.Auth.ClientToken != Placeholder("b-1") || renewed.Auth.LeaseDuration <= 0 {
		t.Fatalf("renew-self = %#v, %v", renewed, err)
	}
	for _, path := range []string{"auth/token/revoke-self", "auth/token/revoke", "auth/token/renew", "auth/token/revoke-accessor"} {
		if _, err := client.Logical().Write(path, map[string]any{"token": "x"}); err == nil || !strings.Contains(err.Error(), "permission denied") {
			t.Fatalf("%s = %v, want permission denied", path, err)
		}
	}
	if _, err := client.Logical().Write("sys/wrapping/unwrap", map[string]any{"token": "s.unknown"}); err == nil {
		t.Fatal("unwrap of a foreign token succeeded")
	}
	if _, err := client.KVv2("kv").Get(ctx, "teams/teal/example"); err != nil {
		t.Fatalf("token stopped working after refused lifecycle calls: %v", err)
	}

	encrypted, err := client.Logical().Write("transit/encrypt/teal-aes", map[string]any{"plaintext": "aGVsbG8="})
	if err != nil || !strings.HasPrefix(encrypted.Data["ciphertext"].(string), "vault:v1:") {
		t.Fatalf("transit pass-through = %v, %v", encrypted, err)
	}
	if event := fixture.recorder.last(); event.Mount != events.MountTransit || event.Method != events.MethodPut {
		t.Fatalf("transit event = %#v", event)
	}

	wrapping := containerClient(t, fixture.socket)
	wrapping.SetWrappingLookupFunc(func(string, string) string { return "60s" })
	wrapped, err := wrapping.Logical().Write("sys/wrapping/wrap", map[string]any{"payload": "value"})
	if err != nil || wrapped.WrapInfo == nil {
		t.Fatalf("wrap = %#v, %v", wrapped, err)
	}
	unwrapped, err := client.Logical().Write("sys/wrapping/unwrap", map[string]any{"token": wrapped.WrapInfo.Token})
	if err != nil || unwrapped.Data["payload"] != "value" {
		t.Fatalf("unwrap of own wrapping token = %#v, %v", unwrapped, err)
	}

	fixture.set(func(view *binding.View, _ *bool) { view.HasToken = false })
	_, err = client.KVv2("kv").Get(ctx, "teams/teal/example")
	var response *api.ResponseError
	if err == nil || !asResponse(err, &response) || response.StatusCode != http.StatusServiceUnavailable || !strings.Contains(err.Error(), "wyrwood") {
		t.Fatalf("no-token request = %v", err)
	}
	if event := fixture.recorder.last(); event.ErrorCode != events.ErrorNoToken {
		t.Fatalf("no-token event = %#v", event)
	}
	fixture.set(func(_ *binding.View, bound *bool) { *bound = false })
	raw := rawRequest(t, fixture.socket, http.MethodGet, "/v1/kv/data/teams/teal/example", nil, nil)
	if raw.status != http.StatusServiceUnavailable || !strings.Contains(raw.body, `"state":"not-bound"`) {
		t.Fatalf("unbound response = %d %s", raw.status, raw.body)
	}
}

func asResponse(err error, target **api.ResponseError) bool {
	return errors.As(err, target)
}

type rawResponse struct {
	status int
	body   string
}

func rawRequest(t *testing.T, socket, method, path string, body []byte, headers map[string]string) rawResponse {
	t.Helper()
	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}}
	request, err := http.NewRequest(method, "http://localhost"+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, _ := io.ReadAll(response.Body)
	return rawResponse{status: response.StatusCode, body: string(data)}
}

func TestProxyStripsCredentialsAndBoundsRequests(t *testing.T) {
	var captured http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		captured = request.Header.Clone()
		_, _ = io.Copy(io.Discard, request.Body)
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"data":{"echo":"real-token-value"}}`))
	}))
	defer upstream.Close()
	view := binding.View{ID: "b-1", OpenBao: protocol.OpenBao{Address: upstream.URL, Namespace: "team-a"},
		Token: openbao.NewToken("real-token-value", time.Hour), HasToken: true}
	fixture := serveFixture(t, view)
	response := rawRequest(t, fixture.socket, http.MethodGet, "/v1/kv/data/x", nil, map[string]string{
		"X-Vault-Token": "client", "Authorization": "Bearer client", "X-Vault-Namespace": "other", "X-Custom": "kept",
	})
	if response.status != http.StatusOK || strings.Contains(response.body, "real-token-value") || !strings.Contains(response.body, Placeholder("b-1")) {
		t.Fatalf("response = %d %s", response.status, response.body)
	}
	if captured.Get("X-Vault-Token") != "real-token-value" || captured.Get("Authorization") != "" ||
		captured.Get("X-Vault-Namespace") != "team-a" || captured.Get("X-Custom") != "kept" {
		t.Fatalf("upstream headers = %v", captured)
	}
	oversize := rawRequest(t, fixture.socket, http.MethodPost, "/v1/kv/data/x", bytes.Repeat([]byte("x"), DefaultMaximumRequestBytes+1), nil)
	if oversize.status != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize status = %d", oversize.status)
	}
	if path := rawRequest(t, fixture.socket, http.MethodGet, "/ui/", nil, nil); path.status != http.StatusNotFound {
		t.Fatalf("non-API path = %d", path.status)
	}
}

func TestMountCategories(t *testing.T) {
	mounts := binding.Mounts{Transit: "transit", SSH: "ssh-ca"}
	for path, want := range map[string]events.Mount{
		"kv/data/x": events.MountKV, "secret/data/x": events.MountKV, "transit/sign/k": events.MountTransit,
		"ssh-ca/sign/r": events.MountSSH, "sys/health": events.MountSys, "auth/token/lookup-self": events.MountAuth,
		"database/creds/x": events.MountOther,
	} {
		if got := mountCategory(path, mounts); got != want {
			t.Errorf("mountCategory(%q) = %s, want %s", path, got, want)
		}
	}
}
