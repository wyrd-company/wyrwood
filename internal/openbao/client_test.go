// ---
// relationships:
//   verifies:
//     - controller
//     - agent
// ---

package openbao

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// setAdversarialEnvironment points every BAO_* variable the OpenBao client
// reads at a value that would redirect, authenticate, or weaken a request.
func setAdversarialEnvironment(t *testing.T) {
	t.Helper()
	decoy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("request reached the address named by the environment")
		w.WriteHeader(http.StatusTeapot)
	}))
	t.Cleanup(decoy.Close)
	t.Setenv("BAO_ADDR", decoy.URL)
	t.Setenv("BAO_AGENT_ADDR", decoy.URL)
	t.Setenv("BAO_TOKEN", "ambient-token")
	t.Setenv("BAO_NAMESPACE", "ambient-namespace")
	t.Setenv("BAO_SKIP_VERIFY", "true")
}

func TestClientIgnoresAmbientAddressTokenAndNamespace(t *testing.T) {
	setAdversarialEnvironment(t)
	type seen struct{ token, namespace string }
	var mu sync.Mutex
	var requests []seen
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests = append(requests, seen{token: r.Header.Get("X-Vault-Token"), namespace: r.Header.Get("X-Vault-Namespace")})
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"secret_id": "unwrapped"}})
	}))
	defer server.Close()
	client, err := NewClient(Endpoint{Address: server.URL, Namespace: "site", Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AppRoleLogin(context.Background(), client, "approle", "role", "secret"); CategoryOf(err) != CategoryInvalid {
		t.Fatalf("AppRoleLogin() = %v, want invalid (no auth in response)", err)
	}
	if secretID, err := UnwrapSecretID(context.Background(), client, "wrapping"); err != nil || secretID != "unwrapped" {
		t.Fatalf("UnwrapSecretID() = %q, %v", secretID, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(requests) != 2 {
		t.Fatalf("server saw %d requests, want 2", len(requests))
	}
	if requests[0] != (seen{namespace: "site"}) {
		t.Errorf("login request = %+v, want no token and namespace site", requests[0])
	}
	if requests[1] != (seen{token: "wrapping", namespace: "site"}) {
		t.Errorf("unwrap request = %+v, want the wrapping token and namespace site", requests[1])
	}
}

func TestClientIgnoresAmbientSkipVerify(t *testing.T) {
	setAdversarialEnvironment(t)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("request completed against an untrusted certificate")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	client, err := NewClient(Endpoint{Address: server.URL, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AppRoleLogin(context.Background(), client, "approle", "role", "secret"); CategoryOf(err) != CategoryUnavailable {
		t.Fatalf("AppRoleLogin() = %v, want unavailable", err)
	}
	if _, err := UnwrapSecretID(context.Background(), client, "wrapping"); CategoryOf(err) != CategoryUnavailable {
		t.Fatalf("UnwrapSecretID() = %v, want unavailable", err)
	}
}

func TestHealthUsesRootNamespaceWithoutChangingClient(t *testing.T) {
	for _, namespace := range []string{"", "site"} {
		t.Run("namespace="+namespace, func(t *testing.T) {
			setAdversarialEnvironment(t)
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != "/v1/sys/health" {
					t.Errorf("health request = %s %s", r.Method, r.URL.Path)
				}
				if got := r.Header.Get("X-Vault-Namespace"); got != "" {
					t.Errorf("health namespace = %q, want root", got)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				if got := r.Header.Get("X-Vault-Token"); got != "" {
					t.Errorf("health request carried a token")
				}
				if got := r.Header.Get("X-Example-Routing"); got != "route" {
					t.Errorf("routing header = %q, want route", got)
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"initialized":true,"sealed":false,"standby":false}`))
			}))
			defer server.Close()
			client, err := NewClient(Endpoint{
				Address: server.URL, Namespace: namespace, Timeout: 5 * time.Second,
				CAPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}),
			})
			if err != nil {
				t.Fatal(err)
			}
			client.SetToken("explicit-token")
			client.AddHeader("X-Example-Routing", "route")
			if err := Health(context.Background(), client); err != nil {
				t.Fatalf("Health() = %v", err)
			}
			if client.Namespace() != namespace || client.Token() != "explicit-token" {
				t.Fatal("Health() changed the source client's namespace or token")
			}
		})
	}
}

func TestHealthCategorizesFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	client, err := NewClient(Endpoint{Address: server.URL, Namespace: "site"})
	if err != nil {
		t.Fatal(err)
	}
	if err := Health(context.Background(), client); err == nil || CategoryOf(err) != CategoryUnavailable {
		t.Fatalf("Health() = %v, want unavailable", err)
	}
}
