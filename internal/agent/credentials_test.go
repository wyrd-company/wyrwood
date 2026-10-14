// ---
// relationships:
//   verifies: agent
// ---

package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wyrd-company/wyrwood/internal/config"
	"github.com/wyrd-company/wyrwood/internal/engine/enginetest"
	"github.com/wyrd-company/wyrwood/internal/events"
	"github.com/wyrd-company/wyrwood/internal/policy"
	"github.com/wyrd-company/wyrwood/internal/protocol"
)

// fakeOpenBao answers unwrap, AppRole login, renew-self, and revoke-self.
// Wrapping tokens in failUnwrap are refused; logins for a role in gates wait
// until the gate closes.
type fakeOpenBao struct {
	server *httptest.Server

	mu         sync.Mutex
	failUnwrap map[string]bool
	gates      map[string]chan struct{}
	logins     map[string]int
	revoked    []string
}

func newFakeOpenBao(t *testing.T) *fakeOpenBao {
	t.Helper()
	fake := &fakeOpenBao{failUnwrap: map[string]bool{}, gates: map[string]chan struct{}{}, logins: map[string]int{}}
	fake.server = httptest.NewServer(http.HandlerFunc(fake.serve))
	t.Cleanup(fake.server.Close)
	return fake
}

func (fake *fakeOpenBao) serve(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("X-Vault-Token")
	w.Header().Set("Content-Type", "application/json")
	switch {
	case strings.HasSuffix(r.URL.Path, "/sys/wrapping/unwrap"):
		fake.mu.Lock()
		fail := fake.failUnwrap[token]
		fake.mu.Unlock()
		if fail {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"secret_id": "secret-" + token}})
	case strings.HasSuffix(r.URL.Path, "/login"):
		var body struct {
			RoleID string `json:"role_id"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		fake.mu.Lock()
		fake.logins[body.RoleID]++
		gate := fake.gates[body.RoleID]
		fake.mu.Unlock()
		if gate != nil {
			<-gate
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"auth": map[string]any{
			"client_token": "token-" + body.RoleID, "lease_duration": 3600, "renewable": true,
		}})
	case strings.HasSuffix(r.URL.Path, "/renew-self"):
		_ = json.NewEncoder(w).Encode(map[string]any{"auth": map[string]any{
			"client_token": token, "lease_duration": 3600, "renewable": true,
		}})
	case strings.HasSuffix(r.URL.Path, "/revoke-self"):
		fake.mu.Lock()
		fake.revoked = append(fake.revoked, token)
		fake.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (fake *fakeOpenBao) gate(role string) chan struct{} {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	gate := make(chan struct{})
	fake.gates[role] = gate
	return gate
}

func (fake *fakeOpenBao) loginCount(role string) int {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	return fake.logins[role]
}

func (fake *fakeOpenBao) wasRevoked(token string) bool {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	for _, revoked := range fake.revoked {
		if revoked == token {
			return true
		}
	}
	return false
}

func newTestCredentials(t *testing.T, fake *fakeOpenBao, request func(string)) *credentials {
	t.Helper()
	manager := newCredentials(5*time.Second, request, func(events.Event) {}, func(string) string { return "" })
	if err := manager.setEndpoint(protocol.OpenBao{Address: fake.server.URL}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(manager.stopAll)
	return manager
}

func credential(binding, role string) protocol.Credential {
	return protocol.Credential{Binding: binding, AppRoleMount: "approle", RoleID: role, WrappedSecretID: "wrap-" + role}
}

func heldValue(manager *credentials, binding string) string {
	token, ok := manager.current(binding)
	if !ok {
		return ""
	}
	return token.Value()
}

func TestStaleLoginCompletionIsRevoked(t *testing.T) {
	ctx := context.Background()
	fake := newFakeOpenBao(t)
	release := fake.gate("role-a")
	manager := newTestCredentials(t, fake, func(string) {})
	stale := make(chan struct{})
	first := manager.begin("bnd-1")
	go func() {
		manager.deliver(ctx, credential("bnd-1", "role-a"), first)
		close(stale)
	}()
	eventually(t, "the first login to start", func() bool { return fake.loginCount("role-a") == 1 })
	manager.deliver(ctx, credential("bnd-1", "role-b"), manager.begin("bnd-1"))
	if got := heldValue(manager, "bnd-1"); got != "token-role-b" {
		t.Fatalf("held token = %q, want token-role-b", got)
	}
	close(release)
	<-stale
	if got := heldValue(manager, "bnd-1"); got != "token-role-b" {
		t.Fatalf("held token after stale completion = %q, want token-role-b", got)
	}
	if !fake.wasRevoked("token-role-a") || fake.wasRevoked("token-role-b") {
		t.Fatalf("revoked = %v, want only token-role-a", fake.revoked)
	}
}

func TestRetiredBindingDiscardsInFlightLogin(t *testing.T) {
	ctx := context.Background()
	fake := newFakeOpenBao(t)
	release := fake.gate("role-a")
	manager := newTestCredentials(t, fake, func(string) {})
	done := make(chan struct{})
	generation := manager.begin("bnd-1")
	go func() {
		manager.deliver(ctx, credential("bnd-1", "role-a"), generation)
		close(done)
	}()
	eventually(t, "the login to start", func() bool { return fake.loginCount("role-a") == 1 })
	manager.retire("bnd-1")
	close(release)
	<-done
	if got := heldValue(manager, "bnd-1"); got != "" {
		t.Fatalf("held token for a retired binding = %q", got)
	}
	if !fake.wasRevoked("token-role-a") {
		t.Fatal("the late token was not revoked")
	}
}

func TestPolicyChangeInvalidatesInFlightDelivery(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fake := newFakeOpenBao(t)
	release := fake.gate("role-a")
	paths := newPaths(t)
	if err := os.MkdirAll(paths.State, 0o700); err != nil {
		t.Fatal(err)
	}
	configuration := config.Agent{ConsumerRoot: filepath.Join(paths.Runtime, "containers"), OpenBaoTimeout: 5 * time.Second}
	instance, err := New(Options{Config: configuration, Paths: paths, Engine: enginetest.New(), Endpoints: probeEndpoints{},
		Hostname: "host-a", CanAssign: func(uint32) bool { return true }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(instance.creds.stopAll)
	set := func(policyName string) protocol.PolicySet {
		return protocol.PolicySet{OpenBao: protocol.OpenBao{Address: fake.server.URL}, Bindings: []protocol.Binding{{
			Binding: "bnd-1", Key: protocol.Key{Kind: protocol.KeyName, Value: "app"},
			Policy: policy.Policy{Name: policyName, Contract: policy.Contract{Enforcement: policy.EnforcementReport}},
		}}}
	}
	instance.applyPolicySet(ctx, set("alpha"))
	done := make(chan struct{})
	generation := instance.creds.begin("bnd-1")
	go func() {
		instance.creds.deliver(ctx, credential("bnd-1", "role-a"), generation)
		close(done)
	}()
	eventually(t, "the login to start", func() bool { return fake.loginCount("role-a") == 1 })
	instance.applyPolicySet(ctx, set("beta"))
	close(release)
	<-done
	if got := heldValue(instance.creds, "bnd-1"); got != "" {
		t.Fatalf("held token from the previous policy = %q", got)
	}
}
