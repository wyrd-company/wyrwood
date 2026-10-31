// ---
// relationships:
//   verifies:
//     - controller
//     - web-interface
// ---

package command

import (
	"context"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/wyrd-company/wyrwood/internal/config"
	"github.com/wyrd-company/wyrwood/internal/controller"
	"github.com/wyrd-company/wyrwood/internal/controller/controllertest"
	"github.com/wyrd-company/wyrwood/internal/controller/store"
	"github.com/wyrd-company/wyrwood/internal/events"
	"github.com/wyrd-company/wyrwood/internal/openbao/baotest"
	"github.com/wyrd-company/wyrwood/internal/web"
	"github.com/wyrd-company/wyrwood/internal/web/oidctest"
)

type heldTokenTransport struct {
	enteredOnce sync.Once
	entered     chan struct{}
	release     chan struct{}
}

func (transport *heldTokenTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL.Path == "/token" {
		transport.enteredOnce.Do(func() { close(transport.entered) })
		<-transport.release
	}
	return http.DefaultTransport.RoundTrip(request)
}

func TestControllerPeerFailureDrainsRealOperatorCallback(t *testing.T) {
	bao := baotest.Start(t)
	role, secret := bao.ControllerCredentials(t)
	provider := oidctest.Start()
	defer provider.Close()
	provider.SignIn(oidctest.Account{Subject: "operator-a", Name: "Example Operator", Groups: []string{"operators"}}, oidctest.TamperNone)
	clientSecret := filepath.Join(t.TempDir(), "client-secret")
	if err := os.WriteFile(clientSecret, []byte(provider.ClientSecret), 0o600); err != nil {
		t.Fatal(err)
	}
	address, state := controllertest.FreeAddress(t), t.TempDir()
	configuration := config.Controller{
		StateDirectory: state, SSHListen: controllertest.FreeAddress(t), HTTPListen: address, SessionTTL: time.Hour,
		OpenBao: config.ControllerOpenBao{Address: bao.Address, Namespace: bao.Namespace, AppRoleMount: "approle",
			RoleID: role, SecretIDFile: secret, TransitMount: "transit", SSHMount: "ssh"},
		OIDC: config.OIDC{Issuer: provider.Issuer(), ClientID: provider.ClientID, ClientSecretFile: clientSecret,
			RedirectURL: "http://" + address + "/auth/callback", GroupsClaim: "groups", AllowedGroups: []string{"operators"}},
	}
	instance, err := controller.New(configuration, controller.Options{})
	if err != nil {
		t.Fatal(err)
	}
	transport := heldTokenTransport{entered: make(chan struct{}), release: make(chan struct{})}
	operators, err := web.New(instance, web.Options{HTTPClient: &http.Client{Transport: &transport}})
	if err != nil {
		instance.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	failure, cancelled := make(chan struct{}), make(chan struct{})
	expected := errors.New("agent runtime failure")
	done := make(chan error, 1)
	go func() {
		err := runControllerServices(ctx, true,
			func(ctx context.Context) error { return instance.Run(ctx, operators.Serve) },
			func(ctx context.Context) error {
				select {
				case <-failure:
				case <-ctx.Done():
				}
				go func() { <-ctx.Done(); close(cancelled) }()
				return expected
			})
		_ = instance.Close()
		done <- err
	}()
	var release sync.Once
	defer func() {
		release.Do(func() { close(transport.release) })
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("combined services did not finish")
		}
	}()
	// Observe the actual listener before starting the sign-in request.
	deadline := time.Now().Add(10 * time.Second)
	for {
		response, err := http.Get("http://" + address + "/healthz")
		if err == nil {
			response.Body.Close()
			if response.StatusCode != http.StatusNoContent {
				t.Fatalf("health status: %d", response.StatusCode)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("HTTP listener did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, CheckRedirect: func(request *http.Request, _ []*http.Request) error {
		if request.URL.Path == "/agents" || request.URL.Path == "/sign-in" {
			return http.ErrUseLastResponse
		}
		return nil
	}}
	type result struct {
		response *http.Response
		err      error
	}
	requestDone := make(chan result, 1)
	go func() {
		response, err := client.PostForm("http://"+address+"/auth/start", nil)
		requestDone <- result{response, err}
	}()
	select {
	case <-transport.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("real callback did not reach token exchange")
	}
	close(failure)
	<-cancelled
	select {
	case err := <-done:
		done <- err
		t.Fatal("combined service closed state while callback was held")
	case <-time.After(50 * time.Millisecond):
	}
	if _, err := instance.Store().Agents(context.Background()); err != nil {
		t.Fatalf("store closed during callback: %v", err)
	}
	locked, err := events.Open(filepath.Join(state, "events", "controller.events"), 10000)
	if locked != nil {
		locked.Close()
	}
	if !errors.Is(err, events.ErrWriterActive) {
		t.Fatalf("controller ownership released: %v", err)
	}
	release.Do(func() { close(transport.release) })
	var response *http.Response
	select {
	case result := <-requestDone:
		if result.err != nil {
			t.Fatal(result.err)
		}
		response = result.response
		defer response.Body.Close()
	case <-time.After(10 * time.Second):
		t.Fatal("callback did not complete")
	}
	if response.StatusCode != http.StatusSeeOther || response.Header.Get("Location") != "/agents" {
		t.Fatalf("callback failed to commit session: %d %s", response.StatusCode, response.Header.Get("Location"))
	}
	select {
	case err := <-done:
		done <- err
		if !errors.Is(err, expected) {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("combined service did not drain")
	}
	// Read durable session state after the actual owner has closed its store.
	reopened, err := store.Open(filepath.Join(state, "controller.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	sessions, err := reopened.OperatorSessions(context.Background(), "operator-a", time.Now())
	if err != nil || len(sessions) != 1 {
		t.Fatalf("persisted sessions: %v, %v", sessions, err)
	}
}
