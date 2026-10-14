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
	"sync/atomic"
	"testing"
	"time"

	"github.com/wyrd-company/wyrwood/internal/config"
	"github.com/wyrd-company/wyrwood/internal/engine/enginetest"
	"github.com/wyrd-company/wyrwood/internal/events"
	"github.com/wyrd-company/wyrwood/internal/openbao/baotest"
	"github.com/wyrd-company/wyrwood/internal/policy"
	"github.com/wyrd-company/wyrwood/internal/protocol"
)

// fakeOpenBao answers unwrap, AppRole login, renew-self, and revoke-self.
// Wrapping tokens in failUnwrap are refused; logins for a role in gates wait
// until the gate closes; a role in ttl receives that lease in seconds; every
// renewal is refused while failRenew is set.
type fakeOpenBao struct {
	server *httptest.Server

	mu         sync.Mutex
	failUnwrap map[string]bool
	failRenew  bool
	ttl        map[string]int
	gates      map[string]chan struct{}
	logins     map[string]int
	revoked    []string
}

func newFakeOpenBao(t *testing.T) *fakeOpenBao {
	t.Helper()
	fake := &fakeOpenBao{failUnwrap: map[string]bool{}, ttl: map[string]int{}, gates: map[string]chan struct{}{}, logins: map[string]int{}}
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
		lease, ok := fake.ttl[body.RoleID]
		fake.mu.Unlock()
		if gate != nil {
			<-gate
		}
		if !ok {
			lease = 3600
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"auth": map[string]any{
			"client_token": "token-" + body.RoleID, "accessor": "accessor" + strings.ReplaceAll(body.RoleID, "-", ""),
			"lease_duration": lease, "renewable": true,
		}})
	case strings.HasSuffix(r.URL.Path, "/renew-self"):
		fake.mu.Lock()
		fail := fake.failRenew
		fake.mu.Unlock()
		if fail {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
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
	manager.retryDelay = 10 * time.Millisecond
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

func TestFailedDeliveryRequestsAnotherCredential(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fake := newFakeOpenBao(t)
	fake.failUnwrap["wrap-role-1"] = true
	var manager *credentials
	var requests atomic.Int32
	manager = newTestCredentials(t, fake, func(binding string) {
		// The controller answers the request with a fresh credential.
		if requests.Add(1) == 1 {
			go manager.deliver(ctx, credential(binding, "role-2"), manager.begin(binding))
		}
	})
	manager.deliver(ctx, credential("bnd-1", "role-1"), manager.begin("bnd-1"))
	eventually(t, "a token after the failed delivery", func() bool { return heldValue(manager, "bnd-1") == "token-role-2" })
	time.Sleep(100 * time.Millisecond)
	if got := requests.Load(); got != 1 {
		t.Fatalf("credential requests = %d, want 1 once a token is held", got)
	}
}

func TestRetryContinuesUntilTheBindingRetires(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fake := newFakeOpenBao(t)
	fake.failUnwrap["wrap-role-1"] = true
	var requests atomic.Int32
	// The controller never issues: each request goes unanswered.
	manager := newTestCredentials(t, fake, func(string) { requests.Add(1) })
	manager.deliver(ctx, credential("bnd-1", "role-1"), manager.begin("bnd-1"))
	eventually(t, "repeated credential requests", func() bool { return requests.Load() >= 2 })
	manager.retire("bnd-1")
	settled := requests.Load()
	time.Sleep(200 * time.Millisecond)
	if got := requests.Load(); got > settled+1 {
		t.Fatalf("credential requests after retirement = %d, want at most %d", got, settled+1)
	}
}

func TestExpiredTokenKeepsRequestingCredentials(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fake := newFakeOpenBao(t)
	fake.ttl["role-1"] = 1
	fake.failRenew = true
	var requests atomic.Int32
	// The controller never issues: each request goes unanswered.
	manager := newTestCredentials(t, fake, func(string) { requests.Add(1) })
	manager.deliver(ctx, credential("bnd-1", "role-1"), manager.begin("bnd-1"))
	if got := heldValue(manager, "bnd-1"); got != "token-role-1" {
		t.Fatalf("held token = %q, want token-role-1", got)
	}
	// Renewal fails once, asks once, and finds the token expired; only the
	// retry loop asks again after that.
	eventually(t, "credential requests after the token expired", func() bool { return requests.Load() >= 3 })
	if got := heldValue(manager, "bnd-1"); got != "" {
		t.Fatalf("held token after expiry = %q", got)
	}
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
	var requests atomic.Int32
	manager := newTestCredentials(t, fake, func(string) { requests.Add(1) })
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

func TestBindingAbsentFromANewPolicySetRevokesItsToken(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fake := newFakeOpenBao(t)
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
	t.Cleanup(instance.shutdown)
	endpoint := protocol.OpenBao{Address: fake.server.URL}
	instance.applyPolicySet(ctx, protocol.PolicySet{OpenBao: endpoint, Bindings: []protocol.Binding{{
		Binding: "bnd-1", Key: protocol.Key{Kind: protocol.KeyName, Value: "app"},
		Policy: policy.Policy{Name: "alpha", Contract: policy.Contract{Enforcement: policy.EnforcementReport}},
	}}})
	instance.creds.deliver(ctx, credential("bnd-1", "role-a"), instance.creds.begin("bnd-1"))
	if got := heldValue(instance.creds, "bnd-1"); got != "token-role-a" {
		t.Fatalf("held token = %q", got)
	}
	// The binding was deleted while the agent was disconnected; the set it
	// receives on reconnecting no longer carries it.
	instance.applyPolicySet(ctx, protocol.PolicySet{OpenBao: endpoint, Bindings: []protocol.Binding{}})
	if got := heldValue(instance.creds, "bnd-1"); got != "" {
		t.Fatalf("held token after the binding left the set = %q", got)
	}
	if !fake.wasRevoked("token-role-a") {
		t.Fatal("the retired binding's token was not revoked")
	}
}

// shortLivedCredential writes an AppRole with the given token time-to-live
// and maximum lifetime and returns a credential for it, as the controller
// would issue.
func shortLivedCredential(t *testing.T, server *baotest.Server, binding string, ttl, maxTTL time.Duration) protocol.Credential {
	t.Helper()
	role := "wyrwood-" + binding
	if _, err := server.Root.Logical().Write("auth/approle/role/"+role, map[string]any{
		"token_ttl": int(ttl / time.Second), "token_max_ttl": int(maxTTL / time.Second), "secret_id_num_uses": 1,
	}); err != nil {
		t.Fatal(err)
	}
	roleID, err := server.Root.Logical().Read("auth/approle/role/" + role + "/role-id")
	if err != nil {
		t.Fatal(err)
	}
	wrapping, err := server.Root.Clone()
	if err != nil {
		t.Fatal(err)
	}
	wrapping.SetToken(baotest.RootToken)
	wrapping.SetWrappingLookupFunc(func(string, string) string { return "60s" })
	wrapped, err := wrapping.Logical().Write("auth/approle/role/"+role+"/secret-id", nil)
	if err != nil || wrapped.WrapInfo == nil {
		t.Fatalf("wrapped secret identifier = %v, %v", wrapped, err)
	}
	return protocol.Credential{Binding: binding, AppRoleMount: "approle", RoleID: roleID.Data["role_id"].(string),
		WrappedSecretID: wrapped.WrapInfo.Token}
}

func TestCappedRenewalRequestsAReplacementBeforeExpiry(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server := baotest.Start(t)
	var manager *credentials
	type request struct{ valid bool }
	requests := make(chan request, 16)
	manager = newCredentials(5*time.Second, func(binding string) {
		_, valid := manager.current(binding)
		requests <- request{valid: valid}
	}, func(events.Event) {}, func(string) string { return "" })
	if err := manager.setEndpoint(protocol.OpenBao{Address: server.Address}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(manager.stopAll)
	// Renewals at 1s and 2s return the full 2s; the one at 3s is capped
	// to the 1s left before the 4s maximum.
	manager.deliver(ctx, shortLivedCredential(t, server, "bnd-1", 2*time.Second, 4*time.Second), manager.begin("bnd-1"))
	if _, ok := manager.current("bnd-1"); !ok {
		t.Fatal("no token after login")
	}
	select {
	case first := <-requests:
		if !first.valid {
			t.Fatal("the first replacement request came after the token expired")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no replacement request before the maximum lifetime")
	}
}

func TestEachInstalledTokenReportsItsAccessor(t *testing.T) {
	ctx := context.Background()
	fake := newFakeOpenBao(t)
	release := fake.gate("role-a")
	manager := newTestCredentials(t, fake, func(string) {})
	var mu sync.Mutex
	var reports []string
	manager.report = func(binding, accessor string) {
		mu.Lock()
		defer mu.Unlock()
		reports = append(reports, binding+"="+accessor)
	}
	reported := func() string {
		mu.Lock()
		defer mu.Unlock()
		return strings.Join(reports, ",")
	}
	stale := make(chan struct{})
	first := manager.begin("bnd-1")
	go func() {
		manager.deliver(ctx, credential("bnd-1", "role-a"), first)
		close(stale)
	}()
	eventually(t, "the first login to start", func() bool { return fake.loginCount("role-a") == 1 })
	manager.deliver(ctx, credential("bnd-1", "role-b"), manager.begin("bnd-1"))
	close(release)
	<-stale
	// The stale token is revoked by the agent and never reported.
	if got := reported(); got != "bnd-1=accessorroleb" {
		t.Fatalf("reports = %s", got)
	}
}
