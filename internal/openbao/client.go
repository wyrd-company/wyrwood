// ---
// relationships:
//   implements:
//     - controller
//     - agent
//   uses: make-openbao-the-secret-and-key-authority
// ---

// Package openbao wraps the official OpenBao Go client with the narrow set of
// operations the controller and the agent perform, and maps every failure to
// a category so raw OpenBao error text never reaches events or output.
package openbao

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/openbao/openbao/api/v2"
)

// Category is a closed failure category.
type Category string

const (
	CategoryUnavailable Category = "unavailable"
	CategoryDenied      Category = "denied"
	CategoryTimeout     Category = "timeout"
	CategoryInvalid     Category = "invalid"
	CategoryNotFound    Category = "not-found"
)

// Error is a categorized OpenBao failure. It deliberately does not wrap the
// underlying error so callers cannot print raw upstream text by accident.
type Error struct {
	Category Category
	Status   int
}

func (err *Error) Error() string { return "openbao " + string(err.Category) }

// CategoryOf returns the category of err, or unavailable for any other error.
func CategoryOf(err error) Category {
	var categorized *Error
	if errors.As(err, &categorized) {
		return categorized.Category
	}
	return CategoryUnavailable
}

func categorize(err error) error {
	if err == nil {
		return nil
	}
	var categorized *Error
	if errors.As(err, &categorized) {
		return err
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return &Error{Category: CategoryTimeout}
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return &Error{Category: CategoryTimeout}
	}
	var response *api.ResponseError
	if errors.As(err, &response) {
		switch {
		case response.StatusCode == http.StatusForbidden || response.StatusCode == http.StatusUnauthorized:
			return &Error{Category: CategoryDenied, Status: response.StatusCode}
		case response.StatusCode == http.StatusNotFound:
			return &Error{Category: CategoryNotFound, Status: response.StatusCode}
		case response.StatusCode == http.StatusBadRequest:
			return &Error{Category: CategoryInvalid, Status: response.StatusCode}
		default:
			return &Error{Category: CategoryUnavailable, Status: response.StatusCode}
		}
	}
	return &Error{Category: CategoryUnavailable}
}

// Endpoint describes how to reach OpenBao.
type Endpoint struct {
	Address   string
	CAFile    string
	CAPEM     []byte
	Namespace string
	Timeout   time.Duration
}

// NewClient returns an OpenBao client that ignores every BAO_* environment
// variable, so no ambient token or address is ever used.
func NewClient(endpoint Endpoint) (*api.Client, error) {
	parsed, err := url.Parse(endpoint.Address)
	if err != nil || !parsed.IsAbs() {
		return nil, &Error{Category: CategoryInvalid}
	}
	configuration := api.NewConfig()
	if configuration.Error != nil {
		return nil, &Error{Category: CategoryInvalid}
	}
	configuration.Address = endpoint.Address
	configuration.MaxRetries = 0
	if endpoint.Timeout > 0 {
		configuration.Timeout = endpoint.Timeout
	}
	tlsConfig := &api.TLSConfig{CACert: endpoint.CAFile, CACertBytes: endpoint.CAPEM}
	if err := configuration.ConfigureTLS(tlsConfig); err != nil {
		return nil, &Error{Category: CategoryInvalid}
	}
	client, err := api.NewClient(configuration)
	if err != nil {
		return nil, &Error{Category: CategoryInvalid}
	}
	client.ClearToken()
	client.SetNamespace(endpoint.Namespace)
	client.SetCloneToken(false)
	return client, nil
}

// AppRoleLogin logs in with an AppRole and returns the token and its lease.
func AppRoleLogin(ctx context.Context, client *api.Client, mount, roleID, secretID string) (Token, error) {
	secret, err := client.Logical().WriteWithContext(ctx, "auth/"+mount+"/login", map[string]any{
		"role_id":   roleID,
		"secret_id": secretID,
	})
	if err != nil {
		return Token{}, categorize(err)
	}
	return tokenFromAuth(secret)
}

// Token is an OpenBao client token held only in memory. String never reveals it.
type Token struct {
	value     string
	Policies  []string
	TTL       time.Duration
	Renewable bool
	Obtained  time.Time
}

// Value returns the token for use in a request header.
func (token Token) Value() string { return token.value }

// Valid reports whether the token is present and unexpired at now.
func (token Token) Valid(now time.Time) bool {
	return token.value != "" && (token.TTL == 0 || now.Before(token.Obtained.Add(token.TTL)))
}

// Expires returns the expiry time, or zero for a non-expiring token.
func (token Token) Expires() time.Time {
	if token.TTL == 0 {
		return time.Time{}
	}
	return token.Obtained.Add(token.TTL)
}

func (token Token) String() string   { return "openbao-token" }
func (token Token) GoString() string { return "openbao-token" }

// NewToken constructs a token, for tests and synthetic responses.
func NewToken(value string, ttl time.Duration, policies ...string) Token {
	return Token{value: value, TTL: ttl, Renewable: true, Policies: policies, Obtained: time.Now()}
}

func tokenFromAuth(secret *api.Secret) (Token, error) {
	if secret == nil || secret.Auth == nil || secret.Auth.ClientToken == "" {
		return Token{}, &Error{Category: CategoryInvalid}
	}
	return Token{
		value:     secret.Auth.ClientToken,
		Policies:  append([]string(nil), secret.Auth.Policies...),
		TTL:       time.Duration(secret.Auth.LeaseDuration) * time.Second,
		Renewable: secret.Auth.Renewable,
		Obtained:  time.Now(),
	}, nil
}

// withToken returns a client clone carrying token and the namespace header.
// It does not use Client.Clone, which reads BAO_* environment variables and
// drops headers unless the source opts in.
func withToken(client *api.Client, token string) (*api.Client, error) {
	clone, err := api.NewClient(client.CloneConfig())
	if err != nil {
		return nil, &Error{Category: CategoryInvalid}
	}
	clone.SetHeaders(client.Headers())
	clone.SetToken(token)
	return clone, nil
}

// Health reports whether OpenBao answers its health endpoint.
func Health(ctx context.Context, client *api.Client) error {
	_, err := client.Sys().HealthWithContext(ctx)
	return categorize(err)
}

func requireString(data map[string]any, key string) (string, error) {
	value, ok := data[key].(string)
	if !ok || value == "" {
		return "", fmt.Errorf("%w", &Error{Category: CategoryInvalid})
	}
	return value, nil
}
