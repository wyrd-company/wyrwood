// ---
// relationships:
//   implements: controller
//   mitigates: controller-token-blast-radius
// ---

package openbao

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/openbao/openbao/api/v2"
	"golang.org/x/crypto/ssh"
)

// ManagedPrefix bounds every policy and AppRole name the controller writes.
const ManagedPrefix = "wyrwood-"

// MaximumWrapTTL bounds response-wrapped secret identifiers.
const MaximumWrapTTL = 5 * time.Minute

// Mounts names the mounts the controller manages.
type Mounts struct {
	AppRole string
	Transit string
	SSH     string
}

// Manager is the controller's OpenBao credential and the operations its
// bounded policy allows.
type Manager struct {
	client   *api.Client
	mounts   Mounts
	roleID   string
	secretID func() (string, error)

	mu    sync.RWMutex
	token Token
}

// NewManager returns a manager that logs in lazily with the controller AppRole.
func NewManager(client *api.Client, mounts Mounts, roleID string, secretID func() (string, error)) *Manager {
	return &Manager{client: client, mounts: mounts, roleID: roleID, secretID: secretID}
}

// Mounts returns the managed mount names.
func (manager *Manager) Mounts() Mounts { return manager.mounts }

// Login obtains a fresh controller token.
func (manager *Manager) Login(ctx context.Context) error {
	secretID, err := manager.secretID()
	if err != nil {
		return &Error{Category: CategoryInvalid}
	}
	token, err := AppRoleLogin(ctx, manager.client, manager.mounts.AppRole, manager.roleID, secretID)
	if err != nil {
		return err
	}
	manager.mu.Lock()
	manager.token = token
	manager.mu.Unlock()
	return nil
}

// Maintain keeps the controller token valid until ctx ends: it renews at half
// the remaining time-to-live and logs in again when renewal fails.
func (manager *Manager) Maintain(ctx context.Context, retry time.Duration) {
	for {
		manager.mu.RLock()
		token := manager.token
		manager.mu.RUnlock()
		wait := retry
		if token.Valid(time.Now()) && token.TTL > 0 {
			wait = time.Until(token.Expires()) / 2
		} else if token.Valid(time.Now()) {
			wait = time.Hour
		}
		if wait < time.Second {
			wait = time.Second
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		if !token.Valid(time.Now()) || !token.Renewable {
			_ = manager.Login(ctx)
			continue
		}
		if err := manager.renew(ctx, token); err != nil {
			_ = manager.Login(ctx)
		}
	}
}

func (manager *Manager) renew(ctx context.Context, token Token) error {
	client, err := withToken(manager.client, token.Value())
	if err != nil {
		return err
	}
	secret, err := client.Auth().Token().RenewSelfWithContext(ctx, 0)
	if err != nil {
		return categorize(err)
	}
	renewed, err := tokenFromAuth(secret)
	if err != nil {
		return err
	}
	manager.mu.Lock()
	manager.token = renewed
	manager.mu.Unlock()
	return nil
}

func (manager *Manager) authorized(ctx context.Context) (*api.Client, error) {
	manager.mu.RLock()
	token := manager.token
	manager.mu.RUnlock()
	if !token.Valid(time.Now()) {
		if err := manager.Login(ctx); err != nil {
			return nil, err
		}
		manager.mu.RLock()
		token = manager.token
		manager.mu.RUnlock()
	}
	return withToken(manager.client, token.Value())
}

func managed(name string) error {
	if !strings.HasPrefix(name, ManagedPrefix) || len(name) <= len(ManagedPrefix) {
		return &Error{Category: CategoryInvalid}
	}
	return nil
}

// WritePolicy writes an ACL policy. OpenBao parses the HCL and rejects it
// when invalid, which is the controller's policy validation.
func (manager *Manager) WritePolicy(ctx context.Context, name, hcl string) error {
	if err := managed(name); err != nil {
		return err
	}
	client, err := manager.authorized(ctx)
	if err != nil {
		return err
	}
	_, err = client.Logical().WriteWithContext(ctx, "sys/policies/acl/"+name, map[string]any{"policy": hcl})
	return categorize(err)
}

// DeletePolicy removes an ACL policy.
func (manager *Manager) DeletePolicy(ctx context.Context, name string) error {
	if err := managed(name); err != nil {
		return err
	}
	client, err := manager.authorized(ctx)
	if err != nil {
		return err
	}
	_, err = client.Logical().DeleteWithContext(ctx, "sys/policies/acl/"+name)
	return categorize(err)
}

// WriteRole creates or updates a binding AppRole: one-use secret identifiers
// and tokens carrying exactly the given policy and time-to-live.
func (manager *Manager) WriteRole(ctx context.Context, role, policyName string, tokenTTL time.Duration) error {
	if err := managed(role); err != nil {
		return err
	}
	client, err := manager.authorized(ctx)
	if err != nil {
		return err
	}
	seconds := strconv.Itoa(int(tokenTTL / time.Second))
	_, err = client.Logical().WriteWithContext(ctx, "auth/"+manager.mounts.AppRole+"/role/"+role, map[string]any{
		"token_policies":     []string{policyName},
		"token_ttl":          seconds,
		"token_max_ttl":      "0",
		"token_type":         "service",
		"secret_id_num_uses": 1,
		"secret_id_ttl":      strconv.Itoa(int(MaximumWrapTTL / time.Second)),
		"bind_secret_id":     true,
	})
	return categorize(err)
}

// DeleteRole removes a binding AppRole.
func (manager *Manager) DeleteRole(ctx context.Context, role string) error {
	if err := managed(role); err != nil {
		return err
	}
	client, err := manager.authorized(ctx)
	if err != nil {
		return err
	}
	_, err = client.Logical().DeleteWithContext(ctx, "auth/"+manager.mounts.AppRole+"/role/"+role)
	return categorize(err)
}

// RoleID reads a binding AppRole's role identifier.
func (manager *Manager) RoleID(ctx context.Context, role string) (string, error) {
	if err := managed(role); err != nil {
		return "", err
	}
	client, err := manager.authorized(ctx)
	if err != nil {
		return "", err
	}
	secret, err := client.Logical().ReadWithContext(ctx, "auth/"+manager.mounts.AppRole+"/role/"+role+"/role-id")
	if err != nil {
		return "", categorize(err)
	}
	if secret == nil {
		return "", &Error{Category: CategoryNotFound}
	}
	return requireString(secret.Data, "role_id")
}

// WrappedSecretID issues one secret identifier for a binding AppRole wrapped
// in a response-wrapping token with the given time-to-live.
func (manager *Manager) WrappedSecretID(ctx context.Context, role string, wrapTTL time.Duration) (string, error) {
	if err := managed(role); err != nil {
		return "", err
	}
	if wrapTTL <= 0 || wrapTTL > MaximumWrapTTL {
		wrapTTL = MaximumWrapTTL
	}
	client, err := manager.authorized(ctx)
	if err != nil {
		return "", err
	}
	client.SetWrappingLookupFunc(func(string, string) string { return wrapTTL.String() })
	secret, err := client.Logical().WriteWithContext(ctx, "auth/"+manager.mounts.AppRole+"/role/"+role+"/secret-id", nil)
	if err != nil {
		return "", categorize(err)
	}
	if secret == nil || secret.WrapInfo == nil || secret.WrapInfo.Token == "" {
		return "", &Error{Category: CategoryInvalid}
	}
	return secret.WrapInfo.Token, nil
}

// TransitKey is a Transit key's public description.
type TransitKey struct {
	Name          string
	Type          string
	LatestVersion int
	PublicKey     ssh.PublicKey
}

// SSHRole is an SSH-engine role's public description.
type SSHRole struct {
	Name         string
	KeyType      string
	AllowedUsers string
	TTL          string
}

// ListTransitKeys lists keys under the managed Transit mount.
func (manager *Manager) ListTransitKeys(ctx context.Context) ([]TransitKey, error) {
	client, err := manager.authorized(ctx)
	if err != nil {
		return nil, err
	}
	names, err := listNames(ctx, client, manager.mounts.Transit+"/keys")
	if err != nil {
		return nil, err
	}
	keys := make([]TransitKey, 0, len(names))
	for _, name := range names {
		key, err := ReadTransitKey(ctx, client, manager.mounts.Transit, name)
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, nil
}

// TransitKeyExists reports whether a named Transit key exists.
func (manager *Manager) TransitKeyExists(ctx context.Context, name string) (bool, error) {
	client, err := manager.authorized(ctx)
	if err != nil {
		return false, err
	}
	secret, err := client.Logical().ReadWithContext(ctx, manager.mounts.Transit+"/keys/"+name)
	if err != nil {
		return false, categorize(err)
	}
	return secret != nil, nil
}

// CreateTransitKey creates a signing key of type ed25519 or rsa-2048/3072/4096.
func (manager *Manager) CreateTransitKey(ctx context.Context, name, keyType string) error {
	switch keyType {
	case "ed25519", "rsa-2048", "rsa-3072", "rsa-4096":
	default:
		return &Error{Category: CategoryInvalid}
	}
	client, err := manager.authorized(ctx)
	if err != nil {
		return err
	}
	_, err = client.Logical().WriteWithContext(ctx, manager.mounts.Transit+"/keys/"+name, map[string]any{"type": keyType})
	return categorize(err)
}

// RotateTransitKey rotates a Transit key to a new version.
func (manager *Manager) RotateTransitKey(ctx context.Context, name string) error {
	client, err := manager.authorized(ctx)
	if err != nil {
		return err
	}
	_, err = client.Logical().WriteWithContext(ctx, manager.mounts.Transit+"/keys/"+name+"/rotate", nil)
	return categorize(err)
}

// ListSSHRoles lists roles under the managed SSH mount.
func (manager *Manager) ListSSHRoles(ctx context.Context) ([]SSHRole, error) {
	client, err := manager.authorized(ctx)
	if err != nil {
		return nil, err
	}
	names, err := listNames(ctx, client, manager.mounts.SSH+"/roles")
	if err != nil {
		return nil, err
	}
	roles := make([]SSHRole, 0, len(names))
	for _, name := range names {
		secret, err := client.Logical().ReadWithContext(ctx, manager.mounts.SSH+"/roles/"+name)
		if err != nil {
			return nil, categorize(err)
		}
		role := SSHRole{Name: name}
		if secret != nil {
			role.KeyType, _ = secret.Data["key_type"].(string)
			role.AllowedUsers, _ = secret.Data["allowed_users"].(string)
			role.TTL = fmt.Sprint(secret.Data["ttl"])
		}
		roles = append(roles, role)
	}
	return roles, nil
}

// SSHRoleExists reports whether a named SSH-engine role exists.
func (manager *Manager) SSHRoleExists(ctx context.Context, name string) (bool, error) {
	client, err := manager.authorized(ctx)
	if err != nil {
		return false, err
	}
	secret, err := client.Logical().ReadWithContext(ctx, manager.mounts.SSH+"/roles/"+name)
	if err != nil {
		return false, categorize(err)
	}
	return secret != nil, nil
}

// CreateSSHRole creates a user-certificate signing role.
func (manager *Manager) CreateSSHRole(ctx context.Context, name, allowedUsers, ttl string) error {
	client, err := manager.authorized(ctx)
	if err != nil {
		return err
	}
	_, err = client.Logical().WriteWithContext(ctx, manager.mounts.SSH+"/roles/"+name, map[string]any{
		"key_type":                "ca",
		"allow_user_certificates": true,
		"allowed_users":           allowedUsers,
		"default_user":            firstUser(allowedUsers),
		"ttl":                     ttl,
		"default_extensions":      map[string]string{"permit-pty": ""},
		"allowed_extensions":      "permit-pty,permit-agent-forwarding,permit-port-forwarding",
	})
	return categorize(err)
}

func firstUser(allowed string) string {
	first, _, _ := strings.Cut(allowed, ",")
	if first == "*" {
		return ""
	}
	return strings.TrimSpace(first)
}

func listNames(ctx context.Context, client *api.Client, path string) ([]string, error) {
	secret, err := client.Logical().ListWithContext(ctx, path)
	if err != nil {
		return nil, categorize(err)
	}
	if secret == nil {
		return nil, nil
	}
	raw, _ := secret.Data["keys"].([]any)
	names := make([]string, 0, len(raw))
	for _, item := range raw {
		if name, ok := item.(string); ok {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names, nil
}

// ReadTransitKey reads a Transit key's latest public key as an SSH key.
func ReadTransitKey(ctx context.Context, client *api.Client, mount, name string) (TransitKey, error) {
	secret, err := client.Logical().ReadWithContext(ctx, mount+"/keys/"+name)
	if err != nil {
		return TransitKey{}, categorize(err)
	}
	if secret == nil {
		return TransitKey{}, &Error{Category: CategoryNotFound}
	}
	key := TransitKey{Name: name}
	key.Type, _ = secret.Data["type"].(string)
	key.LatestVersion = intValue(secret.Data["latest_version"])
	versions, _ := secret.Data["keys"].(map[string]any)
	version, _ := versions[strconv.Itoa(key.LatestVersion)].(map[string]any)
	publicKey, _ := version["public_key"].(string)
	if publicKey != "" {
		parsed, err := parseTransitPublicKey(key.Type, publicKey)
		if err == nil {
			key.PublicKey = parsed
		}
	}
	return key, nil
}

func intValue(value any) int {
	switch typed := value.(type) {
	case json.Number:
		parsed, _ := typed.Int64()
		return int(parsed)
	case float64:
		return int(typed)
	case int:
		return typed
	}
	return 0
}
