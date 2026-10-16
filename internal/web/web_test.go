// ---
// relationships:
//   verifies:
//     - web-interface
//     - authenticate-operators-with-oidc
// ---

package web

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/wyrd-company/wyrwood/internal/config"
	"github.com/wyrd-company/wyrwood/internal/controller"
	"github.com/wyrd-company/wyrwood/internal/controller/controllertest"
	"github.com/wyrd-company/wyrwood/internal/controller/store"
	"github.com/wyrd-company/wyrwood/internal/events"
	"github.com/wyrd-company/wyrwood/internal/openbao/baotest"
	"github.com/wyrd-company/wyrwood/internal/protocol"
	"github.com/wyrd-company/wyrwood/internal/web/oidctest"
)

type harness struct {
	controller *controllertest.Controller
	provider   *oidctest.Provider
	site       *httptest.Server
	server     *Server
}

type swappable struct {
	mu      sync.Mutex
	handler http.Handler
}

func (swap *swappable) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	swap.mu.Lock()
	handler := swap.handler
	swap.mu.Unlock()
	handler.ServeHTTP(writer, request)
}

func startHarness(t *testing.T, sessionTTL time.Duration) *harness {
	t.Helper()
	return startHarnessWithUpdates(t, sessionTTL, config.UpdateChecks{}, nil)
}

func startHarnessWithUpdates(t *testing.T, sessionTTL time.Duration, settings config.UpdateChecks, transport http.RoundTripper) *harness {
	t.Helper()
	bao := baotest.Start(t)
	provider := oidctest.Start()
	t.Cleanup(provider.Close)
	swap := &swappable{handler: http.NotFoundHandler()}
	site := httptest.NewServer(swap)
	t.Cleanup(site.Close)
	secretFile := filepath.Join(t.TempDir(), "client-secret")
	if err := os.WriteFile(secretFile, []byte(provider.ClientSecret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	running := controllertest.StartConfigured(t, bao, t.TempDir(), controllertest.FreeAddress(t), func(configuration *config.Controller) {
		configuration.SessionTTL = sessionTTL
		configuration.UpdateChecks = settings
		configuration.OIDC = config.OIDC{
			ProviderName: "Test ID", Issuer: provider.Issuer(), ClientID: provider.ClientID, ClientSecretFile: secretFile,
			RedirectURL: site.URL + "/auth/callback", GroupsClaim: "groups", AllowedGroups: []string{"wyrwood-operators", "platform-admins"},
		}
	}, nil, controller.Options{ReleaseTransport: transport})
	server, err := New(running.Controller, Options{Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	swap.mu.Lock()
	swap.handler = server.Handler()
	swap.mu.Unlock()
	return &harness{controller: running, provider: provider, site: site, server: server}
}

func browser(t *testing.T) *http.Client {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar, Timeout: 20 * time.Second}
}

type page struct {
	status int
	url    string
	body   string
}

func get(t *testing.T, client *http.Client, target string) page {
	t.Helper()
	response, err := client.Get(target)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	return page{status: response.StatusCode, url: response.Request.URL.String(), body: renderedPage(t, body)}
}

func post(t *testing.T, client *http.Client, target string, form url.Values) page {
	t.Helper()
	response, err := client.PostForm(target, form)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	return page{status: response.StatusCode, url: response.Request.URL.String(), body: renderedPage(t, body)}
}

func (harness *harness) signIn(t *testing.T, client *http.Client, account oidctest.Account, tamper oidctest.Tamper) page {
	t.Helper()
	harness.provider.SignIn(account, tamper)
	return post(t, client, harness.site.URL+"/auth/start", nil)
}

var csrfPattern = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

func csrf(t *testing.T, body string) string {
	t.Helper()
	match := csrfPattern.FindStringSubmatch(body)
	if match == nil {
		t.Fatal("no anti-forgery token in page")
	}
	return match[1]
}

var operator = oidctest.Account{Subject: "subject-ada", Email: "ada@example.com", Name: "Ada", Groups: []string{"engineering", "platform-admins"}}

func TestSignInAdmitsAllowedGroupsAndNamesTheOperator(t *testing.T) {
	harness := startHarness(t, time.Hour)
	client := browser(t)
	if landing := get(t, client, harness.site.URL+"/agents"); !strings.HasSuffix(landing.url, "/sign-in") || !strings.Contains(landing.body, "Continue with Test ID") {
		t.Fatalf("unauthenticated request = %s\n%s", landing.url, landing.body)
	}
	signedIn := harness.signIn(t, client, operator, oidctest.TamperNone)
	if !strings.HasSuffix(signedIn.url, "/agents") || !strings.Contains(signedIn.body, "ada@example.com") ||
		!strings.Contains(signedIn.body, harness.controller.Fingerprint) {
		t.Fatalf("sign-in landed on %s\n%s", signedIn.url, signedIn.body)
	}
	security := get(t, client, harness.site.URL+"/security")
	if !strings.Contains(security.body, "platform-admins") || !strings.Contains(security.body, "This browser") {
		t.Fatalf("security page = %s", security.body)
	}
	found := false
	for _, event := range harness.controller.Events().Recent(100) {
		if event.Operation == events.OperationOperatorSignedIn && event.Outcome == events.OutcomeOK && event.Operator == "subject-ada" {
			found = true
		}
	}
	if !found {
		t.Fatal("no operator-signed-in event naming the operator")
	}

	signOut := post(t, client, harness.site.URL+"/sign-out", url.Values{"csrf": {csrf(t, security.body)}})
	if !strings.HasSuffix(signOut.url, "/sign-in") {
		t.Fatalf("sign-out = %s", signOut.url)
	}
	if after := get(t, client, harness.site.URL+"/agents"); !strings.Contains(after.url, "/sign-in") {
		t.Fatalf("session survived sign-out: %s", after.url)
	}
}

func TestSignInRefusals(t *testing.T) {
	harness := startHarness(t, time.Hour)
	for name, test := range map[string]struct {
		account oidctest.Account
		tamper  oidctest.Tamper
		want    string
	}{
		"no-allowed-group": {oidctest.Account{Subject: "s-1", Email: "eve@example.com", Groups: []string{"engineering"}}, oidctest.TamperNone, "This account can't operate Wyrwood"},
		"no-groups-claim":  {oidctest.Account{Subject: "s-2", Email: "mallory@example.com", OmitGroups: true}, oidctest.TamperNone, "This account can't operate Wyrwood"},
		"issuer":           {operator, oidctest.TamperIssuer, "Sign-in didn't complete"},
		"audience":         {operator, oidctest.TamperAudience, "Sign-in didn't complete"},
		"expired":          {operator, oidctest.TamperExpired, "Sign-in didn't complete"},
		"nonce":            {operator, oidctest.TamperNonce, "Sign-in didn't complete"},
		"signature":        {operator, oidctest.TamperSignature, "Sign-in didn't complete"},
	} {
		t.Run(name, func(t *testing.T) {
			client := browser(t)
			result := harness.signIn(t, client, test.account, test.tamper)
			if !strings.Contains(result.url, "/sign-in") || !strings.Contains(result.body, test.want) {
				t.Fatalf("refusal landed on %s\n%s", result.url, result.body)
			}
			if test.account.Email != "" && test.want == "This account can't operate Wyrwood" && !strings.Contains(result.body, test.account.Email) {
				t.Fatalf("denied page does not name the account: %s", result.body)
			}
			if after := get(t, client, harness.site.URL+"/agents"); !strings.Contains(after.url, "/sign-in") {
				t.Fatal("refused sign-in created a session")
			}
		})
	}
	codes := map[events.ErrorCode]bool{}
	for _, event := range harness.controller.Events().Recent(100) {
		if event.Operation == events.OperationOperatorSignedIn {
			codes[event.ErrorCode] = true
			if event.Outcome != events.OutcomeOK && event.Operator != "" {
				t.Fatalf("refused sign-in event names a subject: %#v", event)
			}
		}
	}
	if !codes[events.ErrorOperatorNotAllowed] || !codes[events.ErrorSignInInvalid] {
		t.Fatalf("refusal codes = %v", codes)
	}
}

func TestCallbackRejectsStateMismatchAndReplay(t *testing.T) {
	harness := startHarness(t, time.Hour)
	client := browser(t)
	client.CheckRedirect = func(request *http.Request, _ []*http.Request) error {
		if strings.Contains(request.URL.Path, "/auth/callback") {
			return http.ErrUseLastResponse
		}
		return nil
	}
	harness.provider.SignIn(operator, oidctest.TamperNone)
	response, err := client.PostForm(harness.site.URL+"/auth/start", nil)
	if err != nil {
		t.Fatal(err)
	}
	callback, _ := url.Parse(response.Header.Get("Location"))
	_ = response.Body.Close()
	query := callback.Query()
	query.Set("state", "forged")
	callback.RawQuery = query.Encode()
	client.CheckRedirect = nil
	if result := get(t, client, callback.String()); !strings.Contains(result.body, "Sign-in didn't complete") {
		t.Fatalf("state mismatch = %s", result.url)
	}
	// The pre-authentication record is single use, so the genuine state now fails too.
	query.Set("state", response.Request.URL.Query().Get("state"))
	if result := get(t, client, callback.String()); !strings.Contains(result.body, "Sign-in didn't complete") {
		t.Fatalf("replayed callback = %s", result.url)
	}
	if result := get(t, browser(t), harness.site.URL+"/auth/callback?code=x&state=y"); !strings.Contains(result.body, "Sign-in didn't complete") {
		t.Fatalf("callback without pre-authentication = %s", result.url)
	}
}

func TestSessionExpiryAndAntiForgery(t *testing.T) {
	harness := startHarness(t, 2*time.Second)
	client := browser(t)
	agents := harness.signIn(t, client, operator, oidctest.TamperNone)
	if forged := post(t, client, harness.site.URL+"/agents/decide", url.Values{"fingerprint": {"x"}, "decision": {"approve"}}); forged.status != http.StatusForbidden {
		t.Fatalf("POST without anti-forgery token = %d", forged.status)
	}
	if forged := post(t, client, harness.site.URL+"/agents/decide", url.Values{"csrf": {"wrong"}, "decision": {"approve"}}); forged.status != http.StatusForbidden {
		t.Fatalf("POST with wrong anti-forgery token = %d", forged.status)
	}
	_ = csrf(t, agents.body)
	site, _ := url.Parse(harness.site.URL)
	var token string
	for _, cookie := range client.Jar.Cookies(site) {
		if cookie.Name == sessionCookie {
			token = cookie.Value
		}
	}
	time.Sleep(2500 * time.Millisecond)
	if expired := get(t, client, harness.site.URL+"/agents"); !strings.Contains(expired.url, "/sign-in") {
		t.Fatalf("expired session = %s", expired.url)
	}
	// The server refuses the session even when a client keeps sending it.
	replay := browser(t)
	replay.Jar.SetCookies(site, []*http.Cookie{{Name: sessionCookie, Value: token, Path: "/"}})
	if expired := get(t, replay, harness.site.URL+"/agents"); !strings.Contains(expired.url, "problem=expired") {
		t.Fatalf("server accepted an expired session: %s", expired.url)
	}
}

func TestOperatorWorkflowThroughPages(t *testing.T) {
	ctx := context.Background()
	harness := startHarness(t, time.Hour)
	client := browser(t)
	harness.signIn(t, client, operator, oidctest.TamperNone)

	key := mustKey(t)
	fingerprint := gossh.FingerprintSHA256(key.PublicKey())
	if _, err := harness.controller.Store().RecordKey(ctx, fingerprint, "host-a", "ssh-ed25519 AAAA", time.Now()); err != nil {
		t.Fatal(err)
	}
	agents := get(t, client, harness.site.URL+"/agents")
	if !strings.Contains(agents.body, "Pending approval") || !strings.Contains(agents.body, fingerprint) {
		t.Fatalf("agents page = %s", agents.body)
	}
	token := csrf(t, agents.body)
	approved := post(t, client, harness.site.URL+"/agents/decide", url.Values{"csrf": {token}, "fingerprint": {fingerprint}, "decision": {"approve"}})
	if !strings.Contains(approved.body, "Agent approved") {
		t.Fatalf("approve = %s", approved.body)
	}

	invalid := post(t, client, harness.site.URL+"/policies", url.Values{"csrf": {token}, "new": {"yes"}, "name": {"teal"},
		"hcl": {`path "kv/*" { capabilities = [`}, "token-ttl": {"1h"}, "mount-target": {"/run/wyrwood"}, "enforcement": {"report"}})
	if invalid.status != http.StatusUnprocessableEntity || !strings.Contains(invalid.body, "OpenBao rejected the HCL policy") {
		t.Fatalf("invalid policy = %d %s", invalid.status, invalid.body)
	}
	short := post(t, client, harness.site.URL+"/policies", url.Values{"csrf": {token}, "new": {"yes"}, "name": {"teal"},
		"hcl": {`path "kv/data/teal/*" { capabilities = ["read"] }`}, "token-ttl": {"2h"}, "token-max-ttl": {"1h"},
		"mount-target": {"/run/wyrwood"}, "enforcement": {"report"}})
	if short.status != http.StatusUnprocessableEntity || !strings.Contains(short.body, "at least the token time-to-live") {
		t.Fatalf("maximum below time-to-live = %d %s", short.status, short.body)
	}
	saved := post(t, client, harness.site.URL+"/policies", url.Values{"csrf": {token}, "new": {"yes"}, "name": {"teal"},
		"hcl":       {`path "kv/data/teal/*" { capabilities = ["read"] }`},
		"token-ttl": {"30m"}, "token-max-ttl": {"4h"}, "mount-target": {"/run/wyrwood"}, "env": {"VAULT_ADDR=unix://{mount-target}/vault.sock"},
		"transit-keys": {""}, "enforcement": {"recreate"}})
	if !strings.Contains(saved.body, "Policy saved") || !strings.Contains(saved.body, "Revision 1") ||
		!regexp.MustCompile(`<input type="text"[^>]*name="token-max-ttl" value="4h"`).MatchString(saved.body) {
		t.Fatalf("save = %s", saved.body)
	}

	containerID := strings.Repeat("d", 64)
	if err := harness.controller.Store().SaveInventory(ctx, "host-a", fingerprint, []protocol.Container{{
		ID: containerID, Name: "web", State: protocol.StateRunning, Image: "example/web:1",
		Keys: []protocol.Key{{Kind: protocol.KeyCompose, Value: "shop/web"}, {Kind: protocol.KeyName, Value: "web"}},
	}}, time.Now()); err != nil {
		t.Fatal(err)
	}
	containers := get(t, client, harness.site.URL+"/containers?agent=host-a")
	if !strings.Contains(containers.body, "Bind by key") || !strings.Contains(containers.body, "shop/web") || !strings.Contains(containers.body, "recreate the container once") {
		t.Fatalf("containers page = %s", containers.body)
	}
	unconfirmed := post(t, client, harness.site.URL+"/bindings", url.Values{"csrf": {token}, "agent": {"host-a"}, "container": {containerID},
		"key": {"compose:shop/web"}, "policy": {"teal"}})
	if !strings.Contains(unconfirmed.body, "Confirm that before binding") {
		t.Fatalf("recreate bind without confirmation = %s", unconfirmed.body)
	}
	bound := post(t, client, harness.site.URL+"/bindings", url.Values{"csrf": {token}, "agent": {"host-a"}, "container": {containerID},
		"key": {"compose:shop/web"}, "policy": {"teal"}, "understood": {"yes"}})
	if !strings.Contains(bound.body, "Policy bound") || !strings.Contains(bound.body, "Bound by compose key") {
		t.Fatalf("bind = %s", bound.body)
	}
	bindings, _ := harness.controller.Store().Bindings(ctx, "host-a")
	if len(bindings) != 1 {
		t.Fatalf("bindings = %#v", bindings)
	}
	confirm := get(t, client, harness.site.URL+"/bindings/"+bindings[0].ID+"/unbind")
	if !strings.Contains(confirm.body, "revokes the container") {
		t.Fatalf("unbind confirmation = %s", confirm.body)
	}
	unbound := post(t, client, harness.site.URL+"/bindings/"+bindings[0].ID+"/unbind", url.Values{"csrf": {token}})
	// No agent is connected and none reported a token, so nothing was revoked.
	if !strings.Contains(unbound.body, "Binding removed") || !strings.Contains(unbound.body, "token could not be revoked") {
		t.Fatalf("unbind = %s", unbound.body)
	}
	for _, path := range []string{"/keys", "/events", "/policies", "/policies/edit?name=teal"} {
		if result := get(t, client, harness.site.URL+path); result.status != http.StatusOK {
			t.Fatalf("%s = %d", path, result.status)
		}
	}
	events := get(t, client, harness.site.URL+"/events")
	if !strings.Contains(events.body, "binding-created") || !strings.Contains(events.body, "ada@example.com") {
		t.Fatalf("events page does not name the operator: %s", events.body)
	}
	var operatorNamed bool
	for _, event := range harness.controller.Events().Recent(100) {
		if event.Operation == "binding-created" && event.Operator == "subject-ada" {
			operatorNamed = true
		}
	}
	if !operatorNamed {
		t.Fatal("binding-created event does not carry the operator")
	}
	_ = store.ErrNotFound
	_ = controller.ErrAgentDisconnected
}

func TestPermitsFollowsOpenBaoGlobs(t *testing.T) {
	hcl := `
path "transit/sign/git-*" { capabilities = ["update"] }
path "ssh/sign/+" { capabilities = ["update"] }
path "transit/sign/read-only" { capabilities = ["read"] }
`
	for target, want := range map[string]bool{
		"transit/sign/git-signing": true, "transit/sign/deploy": false, "ssh/sign/dev": true,
		"ssh/sign/dev/extra": false, "transit/sign/read-only": false,
	} {
		if got := permits(hcl, target); got != want {
			t.Errorf("permits(%q) = %v, want %v", target, got, want)
		}
	}
}

func TestAdmittedGroup(t *testing.T) {
	allowed := []string{"wyrwood-operators", "platform-admins"}
	for _, test := range []struct {
		claim any
		want  string
		ok    bool
	}{
		{nil, "", false},
		{[]any{"engineering"}, "", false},
		{[]any{"engineering", "platform-admins"}, "platform-admins", true},
		{"wyrwood-operators", "wyrwood-operators", true},
	} {
		group, ok := admittedGroup(test.claim, allowed)
		if group != test.want || ok != test.ok {
			t.Errorf("admittedGroup(%v) = %q, %v", test.claim, group, ok)
		}
	}
}

func mustKey(t *testing.T) gossh.Signer {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := gossh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func TestAgentsPageDisplaysBuildVersionsAndUnknownLegacyVersion(t *testing.T) {
	ctx := context.Background()
	harness := startHarness(t, time.Hour)
	harness.server.version = "3.4.5"
	client := browser(t)
	harness.signIn(t, client, operator, oidctest.TamperNone)
	for _, sample := range []struct{ name, version string }{
		{"sample-known", "2.9.1+sample"},
		{"sample-legacy", ""},
		{"sample-same", "3.4.5+sample"},
		{"sample-newer", "4.0.0"},
		{"sample-development", "dev"},
	} {
		key := mustKey(t)
		fingerprint := gossh.FingerprintSHA256(key.PublicKey())
		if _, err := harness.controller.Store().RecordKey(ctx, fingerprint, sample.name, "ssh-ed25519 AAAA", time.Now()); err != nil {
			t.Fatal(err)
		}
		if err := harness.controller.DecideAgent(ctx, fingerprint, true, "sample-operator"); err != nil {
			t.Fatal(err)
		}
		if err := harness.controller.Store().RecordConnection(ctx, fingerprint, sample.version, false, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	result := get(t, client, harness.site.URL+"/agents")
	for _, text := range []string{"Controller version", "3.4.5", "2.9.1+sample", "unknown", "Update available", "Out of date"} {
		if !strings.Contains(result.body, text) {
			t.Errorf("agents page missing %q: %s", text, result.body)
		}
	}
	if count := strings.Count(result.body, "Out of date"); count != 1 {
		t.Fatalf("out-of-date badges = %d, want only the older agent", count)
	}

}

type releaseTransport func(*http.Request) (*http.Response, error)

func (transport releaseTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return transport(request)
}

func TestReleaseObservationReachesAgentsPageAndPreservesOfflineResult(t *testing.T) {
	var offline atomic.Bool
	harness := startHarnessWithUpdates(t, time.Hour, config.UpdateChecks{Enabled: true, Interval: 10 * time.Millisecond, Timeout: time.Second}, releaseTransport(func(request *http.Request) (*http.Response, error) {
		if request.URL.String() != "https://github.com/wyrd-company/wyrwood/releases/latest" {
			t.Errorf("release URL = %s", request.URL)
		}
		if offline.Load() {
			return nil, errors.New("offline")
		}
		return &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": {"https://github.com/wyrd-company/wyrwood/releases/tag/4.5.6"}}, Body: io.NopCloser(strings.NewReader("")), Request: request}, nil
	}))
	harness.server.version = "3.4.5"
	waitRelease := func(unavailable bool) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for {
			status := harness.controller.Updates()
			if status.Latest == "4.5.6" && status.Unavailable == unavailable {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("release observation = %#v", status)
			}
			time.Sleep(time.Millisecond)
		}
	}
	waitRelease(false)
	client := browser(t)
	page := harness.signIn(t, client, operator, oidctest.TamperNone)
	for _, text := range []string{"3.4.5", "Update available", "4.5.6", "Last successful check"} {
		if !strings.Contains(page.body, text) {
			t.Errorf("release page missing %q: %s", text, page.body)
		}
	}
	offline.Store(true)
	waitRelease(true)
	page = get(t, client, harness.site.URL+"/agents")
	for _, text := range []string{"Update check unavailable", "4.5.6", "Update available", "Last successful check"} {
		if !strings.Contains(page.body, text) {
			t.Errorf("offline page missing %q: %s", text, page.body)
		}
	}
	if strings.Contains(page.body, "Up to date.") {
		t.Fatal("failed check claimed current version")
	}
}

func TestBlockedReleaseCheckDoesNotBlockControllerOrPages(t *testing.T) {
	forceStop := make(chan struct{})
	var canceled atomic.Bool
	harness := startHarnessWithUpdates(t, time.Hour, config.UpdateChecks{Enabled: true, Timeout: time.Hour}, releaseTransport(func(request *http.Request) (*http.Response, error) {
		select {
		case <-request.Context().Done():
			canceled.Store(true)
		case <-forceStop:
		}
		return nil, errors.New("release request stopped")
	}))
	client := browser(t)
	page := harness.signIn(t, client, operator, oidctest.TamperNone)
	if !strings.Contains(page.body, "Checking for updates") {
		t.Fatalf("page while public check waits = %s", page.body)
	}
	response, err := client.Get(harness.site.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("health = %d", response.StatusCode)
	}
	stopped := make(chan struct{})
	t.Cleanup(func() { close(forceStop); <-stopped })
	go func() { harness.controller.Stop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("controller shutdown did not cancel release request")
	}
	if !canceled.Load() {
		t.Fatal("controller shutdown left release request running")
	}
}

func TestDisabledReleaseChecksDoNotRunFromControllerOrPages(t *testing.T) {
	var calls atomic.Int32
	harness := startHarnessWithUpdates(t, time.Hour, config.UpdateChecks{}, releaseTransport(func(request *http.Request) (*http.Response, error) {
		calls.Add(1)
		return nil, errors.New("unexpected outbound request")
	}))
	client := browser(t)
	harness.signIn(t, client, operator, oidctest.TamperNone)
	page := get(t, client, harness.site.URL+"/agents")
	if calls.Load() != 0 || !strings.Contains(page.body, "Update checks disabled") {
		t.Fatalf("disabled status, requests=%d: %s", calls.Load(), page.body)
	}
}
