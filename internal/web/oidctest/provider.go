// ---
// relationships:
//   verifies: web-interface
// ---

// Package oidctest runs a minimal OpenID Connect provider for tests: it
// signs whoever the test selects in, and can tamper with each ID token
// property the relying party must verify.
package oidctest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// Account is the identity the provider signs in next.
type Account struct {
	Subject string
	Email   string
	Name    string
	Groups  []string
	// OmitGroups leaves the groups claim out entirely.
	OmitGroups bool
}

// Tamper selects one ID token property to corrupt.
type Tamper string

const (
	TamperNone      Tamper = ""
	TamperIssuer    Tamper = "issuer"
	TamperAudience  Tamper = "audience"
	TamperExpired   Tamper = "expired"
	TamperNonce     Tamper = "nonce"
	TamperSignature Tamper = "signature"
)

// Provider is a running test provider.
type Provider struct {
	Server       *httptest.Server
	ClientID     string
	ClientSecret string

	key   *rsa.PrivateKey
	other *rsa.PrivateKey

	mu      sync.Mutex
	account Account
	tamper  Tamper
	codes   map[string]grant
}

type grant struct {
	account   Account
	nonce     string
	challenge string
	redirect  string
}

// Start runs a provider.
func Start() *Provider {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	provider := &Provider{ClientID: "wyrwood", ClientSecret: "test-client-secret", key: key, other: other, codes: map[string]grant{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", provider.discovery)
	mux.HandleFunc("GET /keys", provider.keys)
	mux.HandleFunc("GET /authorize", provider.authorize)
	mux.HandleFunc("POST /token", provider.token)
	provider.Server = httptest.NewServer(mux)
	return provider
}

// Close stops the provider.
func (provider *Provider) Close() { provider.Server.Close() }

// Issuer returns the issuer URL.
func (provider *Provider) Issuer() string { return provider.Server.URL }

// SignIn selects the account and tampering for the next sign-in.
func (provider *Provider) SignIn(account Account, tamper Tamper) {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	provider.account = account
	provider.tamper = tamper
}

func (provider *Provider) discovery(writer http.ResponseWriter, _ *http.Request) {
	issuer := provider.Issuer()
	_ = json.NewEncoder(writer).Encode(map[string]any{
		"issuer": issuer, "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token",
		"jwks_uri": issuer + "/keys", "response_types_supported": []string{"code"},
		"subject_types_supported": []string{"public"}, "id_token_signing_alg_values_supported": []string{"RS256"},
		"code_challenge_methods_supported": []string{"S256"},
	})
}

func (provider *Provider) keys(writer http.ResponseWriter, _ *http.Request) {
	_ = json.NewEncoder(writer).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &provider.key.PublicKey, KeyID: "test", Algorithm: "RS256", Use: "sig"}}})
}

func (provider *Provider) authorize(writer http.ResponseWriter, request *http.Request) {
	query := request.URL.Query()
	if query.Get("client_id") != provider.ClientID || query.Get("response_type") != "code" ||
		query.Get("code_challenge_method") != "S256" || query.Get("code_challenge") == "" {
		http.Error(writer, "bad authorization request", http.StatusBadRequest)
		return
	}
	code := randomString()
	provider.mu.Lock()
	provider.codes[code] = grant{account: provider.account, nonce: query.Get("nonce"), challenge: query.Get("code_challenge"), redirect: query.Get("redirect_uri")}
	provider.mu.Unlock()
	target, _ := url.Parse(query.Get("redirect_uri"))
	values := target.Query()
	values.Set("code", code)
	values.Set("state", query.Get("state"))
	target.RawQuery = values.Encode()
	http.Redirect(writer, request, target.String(), http.StatusFound)
}

func (provider *Provider) token(writer http.ResponseWriter, request *http.Request) {
	if err := request.ParseForm(); err != nil {
		http.Error(writer, "bad request", http.StatusBadRequest)
		return
	}
	clientID, secret, ok := request.BasicAuth()
	if !ok {
		clientID, secret = request.PostFormValue("client_id"), request.PostFormValue("client_secret")
	}
	provider.mu.Lock()
	granted, found := provider.codes[request.PostFormValue("code")]
	delete(provider.codes, request.PostFormValue("code"))
	tamper := provider.tamper
	provider.mu.Unlock()
	sum := sha256.Sum256([]byte(request.PostFormValue("code_verifier")))
	if clientID != provider.ClientID || secret != provider.ClientSecret || !found ||
		base64.RawURLEncoding.EncodeToString(sum[:]) != granted.challenge || request.PostFormValue("redirect_uri") != granted.redirect {
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusBadRequest)
		_, _ = writer.Write([]byte(`{"error":"invalid_grant"}`))
		return
	}
	now := time.Now()
	claims := map[string]any{
		"iss": provider.Issuer(), "sub": granted.account.Subject, "aud": provider.ClientID,
		"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "nonce": granted.nonce,
		"email": granted.account.Email, "name": granted.account.Name,
	}
	if !granted.account.OmitGroups {
		claims["groups"] = granted.account.Groups
	}
	signingKey := provider.key
	switch tamper {
	case TamperIssuer:
		claims["iss"] = "https://other.example"
	case TamperAudience:
		claims["aud"] = "someone-else"
	case TamperExpired:
		claims["exp"] = now.Add(-time.Hour).Unix()
		claims["iat"] = now.Add(-2 * time.Hour).Unix()
	case TamperNonce:
		claims["nonce"] = "wrong-nonce"
	case TamperSignature:
		signingKey = provider.other
	}
	signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: signingKey}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "test"))
	idToken, _ := jwt.Signed(signer).Claims(claims).Serialize()
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(map[string]any{"access_token": randomString(), "token_type": "Bearer", "expires_in": 300, "id_token": idToken})
}

func randomString() string {
	data := make([]byte, 18)
	_, _ = rand.Read(data)
	return base64.RawURLEncoding.EncodeToString(data)
}
