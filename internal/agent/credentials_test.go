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
	renewals   int
	ttl        map[string]int
	gates      map[string]chan struct{}
	logins     map[string]int
	revoked    []string
	policies   []string
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
		policies := fake.policies
		if policies == nil {
			policies = []string{"wyrwood-example"}
		}
		fake.mu.Unlock()
		if gate != nil {
			<-gate
		}
		if !ok {
			lease = 3600
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"auth": map[string]any{
			"client_token": "token-" + body.RoleID, "accessor": "accessor" + strings.ReplaceAll(body.RoleID, "-", ""),
			"lease_duration": lease, "renewable": true, "policies": policies,
		}})
	case strings.HasSuffix(r.URL.Path, "/renew-self"):
		fake.mu.Lock()
		fake.renewals++
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
	return protocol.Credential{Binding: binding, AppRoleMount: "approle", RoleID: role, WrappedSecretID: "wrap-" + role, Assignment: "assignment"}
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
			go manager.deliver(ctx, credential(binding, "role-2"), manager.begin(binding), []string{"wyrwood-example"}, true)
		}
	})
	manager.deliver(ctx, credential("bnd-1", "role-1"), manager.begin("bnd-1"), []string{"wyrwood-example"}, true)
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
	manager.deliver(ctx, credential("bnd-1", "role-1"), manager.begin("bnd-1"), []string{"wyrwood-example"}, true)
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
	manager.deliver(ctx, credential("bnd-1", "role-1"), manager.begin("bnd-1"), []string{"wyrwood-example"}, true)
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
		manager.deliver(ctx, credential("bnd-1", "role-a"), first, []string{"wyrwood-example"}, true)
		close(stale)
	}()
	eventually(t, "the first login to start", func() bool { return fake.loginCount("role-a") == 1 })
	manager.deliver(ctx, credential("bnd-1", "role-b"), manager.begin("bnd-1"), []string{"wyrwood-example"}, true)
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
		manager.deliver(ctx, credential("bnd-1", "role-a"), generation, []string{"wyrwood-example"}, true)
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
			Policy: (policy.New(policyName, "")).Runtime(policy.DefaultSettings()), Assignment: ((policy.New(policyName,
				"")).Runtime(policy.DefaultSettings())).Identity(),
		}}}
	}
	instance.applyPolicySet(ctx, set("alpha"))
	done := make(chan struct{})
	generation := instance.creds.begin("bnd-1")
	go func() {
		instance.creds.deliver(ctx, credential("bnd-1", "role-a"), generation, []string{"wyrwood-example"}, true)
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
		Policy: (policy.New("alpha", "")).Runtime(policy.DefaultSettings()), Assignment: ((policy.New("alpha", "")).Runtime(policy.DefaultSettings())).Identity(),
	}}})
	instance.creds.deliver(ctx, credential("bnd-1", "role-a"), instance.creds.begin("bnd-1"), []string{"wyrwood-example"}, true)
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
	wrapping, err := server.Root.CloneWithHeaders()
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
		WrappedSecretID: wrapped.WrapInfo.Token, Assignment: "assignment",
	}
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
	if err := manager.setEndpoint(protocol.OpenBao{Address: server.Address, Namespace: server.Namespace}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(manager.stopAll)
	// Renewals at 1s and 2s return the full 2s; the one at 3s is capped
	// to the 1s left before the 4s maximum.
	manager.deliver(ctx, shortLivedCredential(t, server, "bnd-1", 2*time.Second, 4*time.Second), manager.begin("bnd-1"), []string{"default"}, true)
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
	manager.report = func(binding, assignment, accessor string) {
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
		manager.deliver(ctx, credential("bnd-1", "role-a"), first, []string{"wyrwood-example"}, true)
		close(stale)
	}()
	eventually(t, "the first login to start", func() bool { return fake.loginCount("role-a") == 1 })
	manager.deliver(ctx, credential("bnd-1", "role-b"), manager.begin("bnd-1"), []string{"wyrwood-example"}, true)
	close(release)
	<-stale
	// The stale token is revoked by the agent and never reported.
	if got := reported(); got != "bnd-1=accessorroleb" {
		t.Fatalf("reports = %s", got)
	}
}

func TestDeliveryRejectsEveryPolicyOutsideExactBindingSelection(t *testing.T) {
	for name, attached := range map[string][]string{
		"implicit-default":  {"wyrwood-alpha", "wyrwood-beta", "default"},
		"root":              {"root"},
		"controller":        {"wyrwood-alpha", "wyrwood-beta", "controller"},
		"unrelated-managed": {"wyrwood-alpha", "wyrwood-beta", "wyrwood-other"},
		"missing-member":    {"wyrwood-alpha"},
		"duplicate-member":  {"wyrwood-alpha", "wyrwood-beta", "wyrwood-beta"},
		"exact-reordered":   {"wyrwood-beta", "wyrwood-alpha"},
	} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			fake := newFakeOpenBao(t)
			fake.policies = attached
			manager := newTestCredentials(t, fake, func(string) {})
			manager.deliver(ctx, credential("bnd-1", "role-1"), manager.begin("bnd-1"), []string{"wyrwood-alpha", "wyrwood-beta"}, true)
			if name == "exact-reordered" {
				if heldValue(manager, "bnd-1") == "" {
					t.Fatal("exact binding policies rejected")
				}
			} else {
				if heldValue(manager, "bnd-1") != "" {
					t.Fatal("token outside binding's own policies is held")
				}
				if !fake.wasRevoked("token-role-1") {
					t.Fatal("refused token was not revoked")
				}
			}
		})
	}
}

func TestAssignmentChangeRetriesWhenControllerDoesNotDeliver(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fake := newFakeOpenBao(t)
	instance := newRecreateAgent(t, enginetest.New())
	var requests atomic.Int32
	instance.creds.request = func(string) { requests.Add(1) }
	instance.creds.retryDelay = 5 * time.Millisecond
	document := policy.New("example", policy.StarterHCL)
	assignment := func(ttl string) protocol.PolicySet {
		effective := document.Runtime(policy.Settings{TokenTTL: ttl})
		return protocol.PolicySet{OpenBao: protocol.OpenBao{Address: fake.server.URL}, Bindings: []protocol.Binding{{Binding: "bnd-1", Key: protocol.Key{Kind: protocol.KeyName, Value: "app"}, Policy: effective, Assignment: effective.Identity()}}}
	}
	instance.applyPolicySet(ctx, assignment("1h"))
	instance.creds.deliver(ctx, credential("bnd-1", "role-a"), instance.creds.begin("bnd-1"), []string{"wyrwood-example"}, true)
	if heldValue(instance.creds, "bnd-1") == "" {
		t.Fatal("initial token missing")
	}
	before := requests.Load()
	instance.applyPolicySet(ctx, assignment("2h"))
	if heldValue(instance.creds, "bnd-1") != "" {
		t.Fatal("superseded token remains held")
	}
	eventually(t, "repeated requests after missing assignment credential", func() bool { return requests.Load() >= before+2 })
	instance.creds.deliver(ctx, credential("bnd-1", "role-b"), instance.creds.begin("bnd-1"), []string{"wyrwood-example"}, true)
	if heldValue(instance.creds, "bnd-1") != "token-role-b" {
		t.Fatal("recovered assignment token missing")
	}
}

func TestDisabledRenewalExpiresAndReplacesWithoutRenewing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fake := newFakeOpenBao(t)
	fake.ttl["role-1"] = 1
	fake.failRenew = true
	var requests atomic.Int32
	manager := newTestCredentials(t, fake, func(string) { requests.Add(1) })
	manager.deliver(ctx, credential("bnd-1", "role-1"), manager.begin("bnd-1"), []string{"wyrwood-example"}, false)
	initial, _ := manager.current("bnd-1")
	if heldValue(manager, "bnd-1") != "token-role-1" {
		t.Fatal("initial token unavailable")
	}
	eventually(t, "credential replacement retries after expiry", func() bool { return requests.Load() >= 3 })
	if initial.Valid(time.Now()) {
		t.Fatal("replacement requested before token expiry")
	}
	manager.mu.Lock()
	expiredRemoved := manager.held["bnd-1"] == nil
	manager.mu.Unlock()
	if !expiredRemoved {
		t.Fatal("expired credential remained held")
	}
	if heldValue(manager, "bnd-1") != "" {
		t.Fatal("expired token remained usable")
	}
	manager.deliver(ctx, credential("bnd-1", "role-2"), manager.begin("bnd-1"), []string{"wyrwood-example"}, false)
	if heldValue(manager, "bnd-1") != "token-role-2" {
		t.Fatal("replacement token unavailable")
	}
	settled := requests.Load()
	time.Sleep(100 * time.Millisecond)
	if requests.Load() != settled {
		t.Fatal("credential retries continued after replacement")
	}
	fake.mu.Lock()
	renewals := fake.renewals
	fake.mu.Unlock()
	if renewals != 0 {
		t.Fatalf("disabled agent attempted %d renewals", renewals)
	}
	manager.retire("bnd-1")
	if !fake.wasRevoked("token-role-2") {
		t.Fatal("retirement did not revoke replacement")
	}
}

func TestDisabledRenewalRetirementCancelsExpiryReplacement(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fake := newFakeOpenBao(t)
	fake.ttl["role-1"] = 1
	var requests atomic.Int32
	manager := newTestCredentials(t, fake, func(string) { requests.Add(1) })
	manager.deliver(ctx, credential("bnd-1", "role-1"), manager.begin("bnd-1"), []string{"wyrwood-example"}, false)
	manager.retire("bnd-1")
	time.Sleep(1100 * time.Millisecond)
	if requests.Load() != 0 {
		t.Fatal("retired binding requested a replacement")
	}
}

func TestDisabledExpiryCannotDropReplacement(t *testing.T) {
	fake := newFakeOpenBao(t)
	fake.ttl["role-1"] = 1
	var requests atomic.Int32
	manager := newTestCredentials(t, fake, func(string) { requests.Add(1) })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	manager.deliver(ctx, credential("bnd-1", "role-1"), manager.begin("bnd-1"), []string{"wyrwood-example"}, false)
	manager.mu.Lock()
	old := manager.held["bnd-1"]
	manager.mu.Unlock()
	manager.deliver(ctx, credential("bnd-1", "role-2"), manager.begin("bnd-1"), []string{"wyrwood-example"}, false)
	// Model the old expiry callback arriving after a replacement owns the binding.
	// The old credential is already cancelled; a fresh context isolates ownership.
	done := make(chan struct{})
	t.Cleanup(func() { cancel(); <-done })
	go func() { defer close(done); manager.awaitExpiry(ctx, "bnd-1", old) }()
	eventually(t, "the old expiry callback", func() bool {
		select {
		case <-done:
			return true
		default:
			return requests.Load() > 0
		}
	})
	if heldValue(manager, "bnd-1") != "token-role-2" || requests.Load() != 0 {
		t.Fatal("stale expiry changed the replacement")
	}
}
