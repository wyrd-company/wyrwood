// ---
// relationships:
//   implements: web-interface
//   uses: controller
// ---

// Package web serves the embedded React operator interface behind
// OpenID Connect sign-in with group admission.
package web

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/wyrd-company/wyrwood/internal/config"
	"github.com/wyrd-company/wyrwood/internal/controller"
)

//go:embed dist
var assets embed.FS

// Server is the web interface for one controller.
type Server struct {
	controller *controller.Controller
	provider   *provider
	shell      []byte
	version    string
	now        func() time.Time

	deniedMu sync.Mutex
	denied   map[string]string
}

// Options configure the web interface.
type Options struct {
	Version string
	// HTTPClient reaches the identity provider; tests substitute it.
	HTTPClient *http.Client
}

// New returns the web interface for a controller.
func New(instance *controller.Controller, options Options) (*Server, error) {
	configuration := instance.Configuration().OIDC
	secretFile := configuration.ClientSecretFile
	server := &Server{
		controller: instance,
		provider:   newProvider(configuration, func() (string, error) { return config.ReadSecretFile(secretFile) }, options.HTTPClient),
		version:    options.Version,
		now:        func() time.Time { return time.Now().UTC() },
		denied:     map[string]string{},
	}
	if server.version == "" {
		server.version = "dev"
	}
	shell, err := assets.ReadFile("dist/index.html")
	if err != nil {
		return nil, fmt.Errorf("load embedded frontend (run task frontend:build): %w", err)
	}
	server.shell = shell
	return server, nil
}

// Handler returns the routed HTTP handler.
func (server *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	static, _ := fs.Sub(assets, "dist")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(static)))
	mux.HandleFunc("GET /sign-in", server.handleSignInPage)
	mux.HandleFunc("POST /auth/start", server.handleSignInStart)
	mux.HandleFunc("GET /auth/callback", server.handleCallback)
	mux.HandleFunc("GET /healthz", func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusNoContent) })

	authenticated := http.NewServeMux()
	authenticated.HandleFunc("GET /{$}", func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, "/agents", http.StatusSeeOther)
	})
	authenticated.HandleFunc("POST /sign-out", server.handleSignOut)
	authenticated.HandleFunc("GET /agents", server.handleAgents)
	authenticated.HandleFunc("POST /agents/decide", server.handleDecideAgent)
	authenticated.HandleFunc("GET /containers", server.handleContainers)
	authenticated.HandleFunc("POST /bindings", server.handleCreateBinding)
	authenticated.HandleFunc("POST /bindings/preview", server.handlePreviewBinding)
	authenticated.HandleFunc("POST /bindings/{id}/policy", server.handleChangeBinding)
	authenticated.HandleFunc("GET /bindings/{id}/recreate", server.handleConfirmRecreate)
	authenticated.HandleFunc("POST /bindings/{id}/recreate", server.handleRecreate)
	authenticated.HandleFunc("GET /bindings/{id}/unbind", server.handleConfirmUnbind)
	authenticated.HandleFunc("POST /bindings/{id}/unbind", server.handleUnbind)
	authenticated.HandleFunc("GET /policies", server.handlePolicies)
	authenticated.HandleFunc("GET /policies/edit", server.handlePolicyEditor)
	authenticated.HandleFunc("GET /policies/kv", server.handleKVPaths)
	authenticated.HandleFunc("POST /policies", server.handleSavePolicy)
	authenticated.HandleFunc("POST /policies/warnings", server.handlePolicyWarnings)
	authenticated.HandleFunc("GET /keys", server.handleKeys)
	authenticated.HandleFunc("POST /keys/transit", server.handleCreateTransitKey)
	authenticated.HandleFunc("POST /keys/transit/rotate", server.handleRotateTransitKey)
	authenticated.HandleFunc("POST /keys/ssh", server.handleCreateSSHRole)
	authenticated.HandleFunc("GET /events", server.handleEvents)
	authenticated.HandleFunc("GET /settings", server.handleSettings)
	authenticated.HandleFunc("GET /security", server.handleSecurity)
	authenticated.HandleFunc("POST /security/sessions", server.handleEndOtherSessions)
	mux.Handle("/", server.requireSession(authenticated))
	return securityHeaders(mux)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		header := writer.Header()
		header.Set("Content-Security-Policy", "default-src 'none'; connect-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; form-action 'self' *; frame-ancestors 'none'; base-uri 'none'")
		header.Set("X-Content-Type-Options", "nosniff")
		header.Set("Referrer-Policy", "same-origin")
		header.Set("X-Frame-Options", "DENY")
		header.Set("Cache-Control", "no-store")
		next.ServeHTTP(writer, request)
	})
}

// Serve listens on the configured address until ctx ends.
func (server *Server) Serve(ctx context.Context) error {
	listener, err := net.Listen("tcp", server.controller.Configuration().HTTPListen)
	if err != nil {
		return err
	}
	httpServer := &http.Server{Handler: server.Handler(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 2 * time.Minute, MaxHeaderBytes: 64 << 10}
	ctx, cancel := context.WithCancel(ctx)
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		<-ctx.Done()
		// Listener closure ends Serve before active handlers finish. Retain
		// controller state until all admitted requests have returned.
		_ = httpServer.Shutdown(context.Background())
	}()
	defer func() { cancel(); <-drained }()
	if err := httpServer.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func (server *Server) render(writer http.ResponseWriter, request *http.Request, name string, data any) {
	// encoding/json escapes HTML delimiters, including </script>, so page data
	// cannot terminate this inert data block. All executable code is bundled.
	payload, err := json.Marshal(struct {
		Page string `json:"page"`
		Data any    `json:"data"`
	}{name, data})
	if err != nil {
		http.Error(writer, "The page could not be rendered.", http.StatusInternalServerError)
		return
	}
	block := append([]byte(`<script id="wyrwood-page" type="application/json">`), payload...)
	block = append(block, []byte(`</script>`)...)
	body := bytes.Replace(server.shell, []byte("<!--wyrwood-page-->"), block, 1)
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = writer.Write(body)
}

func (server *Server) controllerHost() string {
	redirect, err := url.Parse(server.controller.Configuration().OIDC.RedirectURL)
	if err != nil {
		return ""
	}
	return redirect.Host
}

func ago(value time.Time) string {
	if value.IsZero() {
		return "never"
	}
	return humanDuration(time.Since(value)) + " ago"
}

func humanDuration(duration time.Duration) string {
	switch {
	case duration < 0:
		duration = 0
		fallthrough
	case duration < time.Minute:
		return strconv.Itoa(int(duration/time.Second)) + " s"
	case duration < time.Hour:
		return strconv.Itoa(int(duration/time.Minute)) + " min"
	case duration < 48*time.Hour:
		return strconv.Itoa(int(duration/time.Hour)) + " h"
	default:
		return strconv.Itoa(int(duration/(24*time.Hour))) + " d"
	}
}
