// ---
// relationships:
//   verifies: controller
// ---

package openbao

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/openbao/openbao/api/v2"
)

type revocationTransport func(*http.Request) (*http.Response, error)

func (transport revocationTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return transport(request)
}

// TestOverlappingRevocations holds both client calls in flight and injects the
// revoke-accessor response observed during OpenBao's token deletion window.
// Self-revocation and token-validity checks use the real OpenBao server.
func TestOverlappingRevocations(t *testing.T) {
	server, manager := testManager(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	issued, err := server.Root.Auth().Token().Create(&api.TokenCreateRequest{TTL: "1h"})
	if err != nil {
		t.Fatal(err)
	}
	token, err := tokenFromAuth(issued)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := withToken(server.Root, token.Value())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Auth().Token().LookupSelfWithContext(ctx); err != nil {
		t.Fatalf("token authentication before revocation = %v", categorize(err))
	}
	accessorStarted := make(chan struct{})
	selfInvalidated := make(chan struct{})
	releaseSelf := make(chan struct{})
	configuration := manager.client.CloneConfig()
	upstream := configuration.HttpClient.Transport
	configuration.HttpClient.Transport = revocationTransport(func(request *http.Request) (*http.Response, error) {
		switch request.URL.Path {
		case "/v1/auth/token/revoke-accessor":
			defer request.Body.Close()
			var payload struct{ Accessor string }
			if err := json.NewDecoder(request.Body).Decode(&payload); err != nil || payload.Accessor != token.Accessor {
				t.Error("accessor revocation did not carry the reported token accessor")
			}
			close(accessorStarted)
			select {
			case <-selfInvalidated:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			return &http.Response{
				StatusCode: http.StatusBadRequest,
				Header:     http.Header{"Content-Type": {"application/json"}},
				Body:       io.NopCloser(strings.NewReader(`{"errors":["token not found"]}`)),
				Request:    request,
			}, nil
		case "/v1/auth/token/revoke-self":
			select {
			case <-accessorStarted:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			response, err := upstream.RoundTrip(request)
			close(selfInvalidated)
			select {
			case <-releaseSelf:
			case <-ctx.Done():
			}
			return response, err
		default:
			return upstream.RoundTrip(request)
		}
	})
	client, err := api.NewClient(configuration)
	if err != nil {
		t.Fatal(err)
	}
	client.SetNamespace(server.Namespace)
	manager.client = client
	accessorResult, selfResult := make(chan error, 1), make(chan error, 1)
	var calls sync.WaitGroup
	calls.Add(2)
	t.Cleanup(calls.Wait)
	go func() {
		defer calls.Done()
		accessorResult <- manager.RevokeAccessor(ctx, token.Accessor)
	}()
	go func() {
		defer calls.Done()
		selfResult <- RevokeSelf(ctx, client, token)
	}()
	revokeErr := <-accessorResult
	// The self-revocation response is still held at the client seam here.
	if _, err := reader.Auth().Token().LookupSelfWithContext(ctx); CategoryOf(categorize(err)) != CategoryDenied {
		t.Fatalf("token authentication after overlapping revocation = %v, want denied", categorize(err))
	}
	close(releaseSelf)
	if err := <-selfResult; err != nil {
		t.Fatalf("RevokeSelf() = %v", err)
	}
	if revokeErr != nil {
		t.Fatalf("RevokeAccessor() during self-revocation = %v, want success", revokeErr)
	}
}

func TestRevokeAccessorRejectsOtherFailures(t *testing.T) {
	for _, test := range []struct {
		name     string
		status   int
		body     string
		category Category
	}{
		{"denied", http.StatusForbidden, `{"errors":["permission denied"]}`, CategoryDenied},
		{"unauthorized", http.StatusUnauthorized, `{"errors":["token not found"]}`, CategoryDenied},
		{"server-error", http.StatusInternalServerError, `{"errors":["token not found"]}`, CategoryUnavailable},
		{"unavailable", http.StatusServiceUnavailable, `{"errors":["token not found"]}`, CategoryUnavailable},
		{"not-found-route", http.StatusNotFound, `{"errors":["token not found"]}`, CategoryNotFound},
		{"other-invalid", http.StatusBadRequest, `{"errors":["missing accessor"]}`, CategoryInvalid},
		{"substring", http.StatusBadRequest, `{"errors":["other token not found error"]}`, CategoryInvalid},
		{"additional-error", http.StatusBadRequest, `{"errors":["token not found","storage failure"]}`, CategoryInvalid},
		{"duplicate-error", http.StatusBadRequest, `{"errors":["token not found","token not found"]}`, CategoryInvalid},
		{"empty-errors", http.StatusBadRequest, `{"errors":[]}`, CategoryInvalid},
	} {
		t.Run(test.name, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				requests.Add(1)
				if request.URL.Path != "/v1/auth/token/revoke-accessor" {
					t.Errorf("unexpected request to %s", request.URL.Path)
				}
				writer.Header().Set("Content-Type", "application/json")
				writer.WriteHeader(test.status)
				_, _ = io.WriteString(writer, test.body)
			}))
			defer server.Close()
			client, err := NewClient(Endpoint{Address: server.URL})
			if err != nil {
				t.Fatal(err)
			}
			manager := NewManager(client, Mounts{}, "", nil)
			manager.token = NewToken("controller-token", 0)
			err = manager.RevokeAccessor(context.Background(), "exampleaccessor")
			if err == nil || CategoryOf(err) != test.category {
				t.Fatalf("RevokeAccessor() = %v, want %s failure", err, test.category)
			}
			if requests.Load() != 1 {
				t.Fatalf("requests = %d, want one revocation", requests.Load())
			}
		})
	}
}
