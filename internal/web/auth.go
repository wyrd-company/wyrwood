// ---
// relationships:
//   implements: web-interface
//   uses: authenticate-operators-with-oidc
//   exposes: identity-provider-grants-operator-access
// ---

package web

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/wyrd-company/wyrwood/internal/config"
	"github.com/wyrd-company/wyrwood/internal/controller/store"
	"github.com/wyrd-company/wyrwood/internal/events"
)

const (
	sessionCookie      = "wyrwood_session"
	preAuthCookie      = "wyrwood_signin"
	preAuthTTL         = 10 * time.Minute
	maximumPreAuth     = 1024
	discoveryRetry     = 30 * time.Second
	providerHTTPTimout = 10 * time.Second
)

var (
	errProviderUnavailable = errors.New("identity provider unavailable")
	errSignInInvalid       = errors.New("sign-in invalid")
	errNotAllowed          = errors.New("operator not allowed")
)

// provider is the OpenID Connect relying party. Discovery and keys are
// fetched lazily from the configured issuer and cached.
type provider struct {
	config       config.OIDC
	clientSecret func() (string, error)
	httpClient   *http.Client

	mu        sync.Mutex
	discovery *oidc.Provider
	verifier  *oidc.IDTokenVerifier
	fetched   time.Time
	failedAt  time.Time

	pendingMu sync.Mutex
	pending   map[string]preAuth
}

type preAuth struct {
	state    string
	nonce    string
	verifier string
	expires  time.Time
}

func newProvider(configuration config.OIDC, clientSecret func() (string, error), client *http.Client) *provider {
	if client == nil {
		client = &http.Client{Timeout: providerHTTPTimout}
	}
	return &provider{config: configuration, clientSecret: clientSecret, httpClient: client, pending: map[string]preAuth{}}
}

func (provider *provider) context(ctx context.Context) context.Context {
	return oidc.ClientContext(ctx, provider.httpClient)
}

// load returns the discovered provider, refreshing a failed discovery no
// more often than every thirty seconds.
func (provider *provider) load(ctx context.Context) (*oidc.Provider, *oidc.IDTokenVerifier, error) {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	if provider.discovery != nil {
		return provider.discovery, provider.verifier, nil
	}
	if time.Since(provider.failedAt) < discoveryRetry && !provider.failedAt.IsZero() {
		return nil, nil, errProviderUnavailable
	}
	discoveryCtx, cancel := context.WithTimeout(provider.context(ctx), providerHTTPTimout)
	defer cancel()
	discovered, err := oidc.NewProvider(discoveryCtx, provider.config.Issuer)
	if err != nil {
		provider.failedAt = time.Now()
		return nil, nil, errProviderUnavailable
	}
	provider.discovery = discovered
	provider.verifier = discovered.Verifier(&oidc.Config{ClientID: provider.config.ClientID})
	provider.fetched = time.Now()
	return provider.discovery, provider.verifier, nil
}

// reachable reports whether discovery succeeded and when.
func (provider *provider) reachable(ctx context.Context) (bool, time.Time) {
	_, _, err := provider.load(ctx)
	provider.mu.Lock()
	defer provider.mu.Unlock()
	return err == nil, provider.fetched
}

func (provider *provider) oauth(discovered *oidc.Provider) (*oauth2.Config, error) {
	secret, err := provider.clientSecret()
	if err != nil {
		return nil, errProviderUnavailable
	}
	return &oauth2.Config{
		ClientID: provider.config.ClientID, ClientSecret: secret, RedirectURL: provider.config.RedirectURL,
		Endpoint: discovered.Endpoint(), Scopes: []string{oidc.ScopeOpenID, "profile", "email", "groups"},
	}, nil
}

func randomToken(bytes int) string {
	data := make([]byte, bytes)
	if _, err := rand.Read(data); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(data)
}

// start begins the authorization-code flow and returns the provider URL and
// the pre-authentication cookie value.
func (provider *provider) start(ctx context.Context) (string, string, error) {
	discovered, _, err := provider.load(ctx)
	if err != nil {
		return "", "", err
	}
	oauthConfig, err := provider.oauth(discovered)
	if err != nil {
		return "", "", err
	}
	pending := preAuth{state: randomToken(24), nonce: randomToken(24), verifier: oauth2.GenerateVerifier(), expires: time.Now().Add(preAuthTTL)}
	key := randomToken(24)
	provider.pendingMu.Lock()
	now := time.Now()
	for candidate, entry := range provider.pending {
		if now.After(entry.expires) {
			delete(provider.pending, candidate)
		}
	}
	if len(provider.pending) >= maximumPreAuth {
		provider.pendingMu.Unlock()
		return "", "", errProviderUnavailable
	}
	provider.pending[key] = pending
	provider.pendingMu.Unlock()
	target := oauthConfig.AuthCodeURL(pending.state, oidc.Nonce(pending.nonce), oauth2.S256ChallengeOption(pending.verifier))
	return target, key, nil
}

// identity is the admitted operator from a verified ID token.
type identity struct {
	Subject       string
	DisplayName   string
	Email         string
	AdmittedGroup string
}

// finish completes the flow: it checks state against the pre-authentication
// cookie, exchanges the code with the PKCE verifier and client secret,
// verifies the ID token's signature, issuer, audience, expiry, and nonce,
// and admits the account by group. A refused account's display name is
// returned so the sign-in page can name it.
func (provider *provider) finish(ctx context.Context, preAuthKey string, query url.Values) (identity, error) {
	provider.pendingMu.Lock()
	pending, ok := provider.pending[preAuthKey]
	delete(provider.pending, preAuthKey)
	provider.pendingMu.Unlock()
	if !ok || time.Now().After(pending.expires) || query.Get("state") == "" ||
		subtle.ConstantTimeCompare([]byte(query.Get("state")), []byte(pending.state)) != 1 || query.Get("code") == "" {
		return identity{}, errSignInInvalid
	}
	discovered, verifier, err := provider.load(ctx)
	if err != nil {
		return identity{}, err
	}
	oauthConfig, err := provider.oauth(discovered)
	if err != nil {
		return identity{}, err
	}
	exchangeCtx, cancel := context.WithTimeout(provider.context(ctx), providerHTTPTimout)
	defer cancel()
	token, err := oauthConfig.Exchange(exchangeCtx, query.Get("code"), oauth2.VerifierOption(pending.verifier))
	if err != nil {
		var retrieve *oauth2.RetrieveError
		if errors.As(err, &retrieve) {
			return identity{}, errSignInInvalid
		}
		return identity{}, errProviderUnavailable
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return identity{}, errSignInInvalid
	}
	idToken, err := verifier.Verify(exchangeCtx, rawIDToken)
	if err != nil {
		return identity{}, errSignInInvalid
	}
	if subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(pending.nonce)) != 1 {
		return identity{}, errSignInInvalid
	}
	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		return identity{}, errSignInInvalid
	}
	result := identity{Subject: idToken.Subject}
	result.Email, _ = claims["email"].(string)
	result.DisplayName, _ = claims["name"].(string)
	if result.DisplayName == "" {
		result.DisplayName, _ = claims["preferred_username"].(string)
	}
	if result.DisplayName == "" {
		result.DisplayName = result.Email
	}
	if result.Subject == "" || len(result.Subject) > 255 {
		return identity{}, errSignInInvalid
	}
	group, ok := admittedGroup(claims[provider.config.GroupsClaim], provider.config.AllowedGroups)
	if !ok {
		return result, errNotAllowed
	}
	result.AdmittedGroup = group
	return result, nil
}

// admittedGroup returns the first allowed group present in the groups claim.
func admittedGroup(claim any, allowed []string) (string, bool) {
	var groups []string
	switch typed := claim.(type) {
	case []any:
		for _, item := range typed {
			if text, ok := item.(string); ok {
				groups = append(groups, text)
			}
		}
	case string:
		groups = append(groups, typed)
	}
	present := map[string]bool{}
	for _, group := range groups {
		present[group] = true
	}
	for _, group := range allowed {
		if present[group] {
			return group, true
		}
	}
	return "", false
}

// sessionContext is the authenticated operator for one request.
type sessionContext struct {
	session  store.WebSession
	operator store.Operator
}

type sessionKey struct{}

func operatorFrom(ctx context.Context) (sessionContext, bool) {
	value, ok := ctx.Value(sessionKey{}).(sessionContext)
	return value, ok
}

func (server *Server) secureCookies() bool {
	return !strings.HasPrefix(server.controller.Configuration().OIDC.RedirectURL, "http://")
}

func (server *Server) setCookie(writer http.ResponseWriter, name, value, path string, expires time.Time) {
	cookie := &http.Cookie{Name: name, Value: value, Path: path, HttpOnly: true, Secure: server.secureCookies(), SameSite: http.SameSiteLaxMode}
	if !expires.IsZero() {
		cookie.Expires = expires
		cookie.MaxAge = int(time.Until(expires) / time.Second)
	}
	if value == "" {
		cookie.MaxAge = -1
	}
	http.SetCookie(writer, cookie)
}

// requireSession admits only requests with a valid session and, for
// state-changing methods, a matching anti-forgery token.
func (server *Server) requireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		cookie, err := request.Cookie(sessionCookie)
		if err != nil || cookie.Value == "" {
			http.Redirect(writer, request, "/sign-in", http.StatusSeeOther)
			return
		}
		session, err := server.controller.Store().Session(request.Context(), store.HashSessionToken(cookie.Value), server.now())
		if err != nil {
			server.setCookie(writer, sessionCookie, "", "/", time.Time{})
			http.Redirect(writer, request, "/sign-in?problem=expired", http.StatusSeeOther)
			return
		}
		if request.Method != http.MethodGet && request.Method != http.MethodHead {
			if err := request.ParseForm(); err != nil ||
				subtle.ConstantTimeCompare([]byte(request.PostFormValue("csrf")), []byte(session.CSRF)) != 1 {
				http.Error(writer, "The form expired. Reload the page and try again.", http.StatusForbidden)
				return
			}
		}
		operator, _ := server.controller.Store().Operator(request.Context(), session.Subject)
		ctx := context.WithValue(request.Context(), sessionKey{}, sessionContext{session: session, operator: operator})
		next.ServeHTTP(writer, request.WithContext(ctx))
	})
}

func (server *Server) handleSignInPage(writer http.ResponseWriter, request *http.Request) {
	if cookie, err := request.Cookie(sessionCookie); err == nil && cookie.Value != "" {
		if _, err := server.controller.Store().Session(request.Context(), store.HashSessionToken(cookie.Value), server.now()); err == nil {
			http.Redirect(writer, request, "/agents", http.StatusSeeOther)
			return
		}
	}
	issuer, _ := url.Parse(server.controller.Configuration().OIDC.Issuer)
	data := signInPage{layout: layout{Title: "Sign in", Current: "sign-in"}, Provider: server.controller.Configuration().OIDC.ProviderName,
		IssuerHost: issuer.Host, Version: server.version}
	switch request.URL.Query().Get("problem") {
	case "denied":
		data.Problem = "denied"
		data.Account = server.takeDenied(request)
	case "unavailable":
		data.Problem = "unavailable"
	case "invalid":
		data.Problem = "invalid"
	case "expired":
		data.Problem = "expired"
	}
	server.render(writer, request, "sign-in", data)
}

func (server *Server) handleSignInStart(writer http.ResponseWriter, request *http.Request) {
	target, key, err := server.provider.start(request.Context())
	if err != nil {
		server.controller.RecordOperatorEvent(events.OperationOperatorSignedIn, "", events.ErrorIdentityProviderUnavailable, 0)
		http.Redirect(writer, request, "/sign-in?problem=unavailable", http.StatusSeeOther)
		return
	}
	server.setCookie(writer, preAuthCookie, key, "/auth/", time.Now().Add(preAuthTTL))
	http.Redirect(writer, request, target, http.StatusSeeOther)
}

func (server *Server) handleCallback(writer http.ResponseWriter, request *http.Request) {
	started := server.now()
	cookie, err := request.Cookie(preAuthCookie)
	server.setCookie(writer, preAuthCookie, "", "/auth/", time.Time{})
	key := ""
	if err == nil {
		key = cookie.Value
	}
	admitted, err := server.provider.finish(request.Context(), key, request.URL.Query())
	switch {
	case errors.Is(err, errNotAllowed):
		server.controller.RecordOperatorEvent(events.OperationOperatorSignedIn, "", events.ErrorOperatorNotAllowed, server.now().Sub(started))
		server.rememberDenied(writer, admitted)
		http.Redirect(writer, request, "/sign-in?problem=denied", http.StatusSeeOther)
		return
	case errors.Is(err, errProviderUnavailable):
		server.controller.RecordOperatorEvent(events.OperationOperatorSignedIn, "", events.ErrorIdentityProviderUnavailable, server.now().Sub(started))
		http.Redirect(writer, request, "/sign-in?problem=unavailable", http.StatusSeeOther)
		return
	case err != nil:
		server.controller.RecordOperatorEvent(events.OperationOperatorSignedIn, "", events.ErrorSignInInvalid, server.now().Sub(started))
		http.Redirect(writer, request, "/sign-in?problem=invalid", http.StatusSeeOther)
		return
	}
	ctx := request.Context()
	now := server.now()
	if err := server.controller.Store().RecordOperator(ctx, store.Operator{
		Subject: admitted.Subject, DisplayName: bounded(admitted.DisplayName, 255), Email: bounded(admitted.Email, 255), LastSignIn: now,
	}); err != nil {
		http.Redirect(writer, request, "/sign-in?problem=invalid", http.StatusSeeOther)
		return
	}
	token := randomToken(32)
	expires := now.Add(server.controller.Configuration().SessionTTL)
	if err := server.controller.Store().CreateSession(ctx, store.WebSession{
		IDHash: store.HashSessionToken(token), Subject: admitted.Subject, AdmittedGroup: admitted.AdmittedGroup,
		CSRF: randomToken(24), CreatedAt: now, ExpiresAt: expires,
	}); err != nil {
		http.Redirect(writer, request, "/sign-in?problem=invalid", http.StatusSeeOther)
		return
	}
	_ = server.controller.Store().PruneSessions(ctx, now)
	server.controller.RecordOperatorEvent(events.OperationOperatorSignedIn, admitted.Subject, events.ErrorNone, server.now().Sub(started))
	server.setCookie(writer, sessionCookie, token, "/", expires)
	http.Redirect(writer, request, "/agents", http.StatusSeeOther)
}

func (server *Server) handleSignOut(writer http.ResponseWriter, request *http.Request) {
	current, _ := operatorFrom(request.Context())
	_ = server.controller.Store().DeleteSession(request.Context(), current.session.IDHash)
	server.controller.RecordOperatorEvent(events.OperationOperatorSignedOut, current.session.Subject, events.ErrorNone, 0)
	server.setCookie(writer, sessionCookie, "", "/", time.Time{})
	http.Redirect(writer, request, "/sign-in", http.StatusSeeOther)
}

// rememberDenied keeps the refused account's name for the sign-in page in
// server memory only, keyed by a short-lived cookie.
func (server *Server) rememberDenied(writer http.ResponseWriter, refused identity) {
	name := refused.Email
	if name == "" {
		name = refused.DisplayName
	}
	if name == "" {
		return
	}
	key := randomToken(16)
	server.deniedMu.Lock()
	if len(server.denied) > maximumPreAuth {
		server.denied = map[string]string{}
	}
	server.denied[key] = bounded(name, 255)
	server.deniedMu.Unlock()
	server.setCookie(writer, "wyrwood_denied", key, "/sign-in", time.Now().Add(time.Minute))
}

func (server *Server) takeDenied(request *http.Request) string {
	cookie, err := request.Cookie("wyrwood_denied")
	if err != nil {
		return ""
	}
	server.deniedMu.Lock()
	defer server.deniedMu.Unlock()
	name := server.denied[cookie.Value]
	delete(server.denied, cookie.Value)
	return name
}

func bounded(value string, maximum int) string {
	if len(value) > maximum {
		return value[:maximum]
	}
	return value
}
