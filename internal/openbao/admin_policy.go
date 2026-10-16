// ---
// relationships:
//   implements: openbao-admin-access
// ---

package openbao

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/openbao/openbao/api/v2"
)

const (
	AdminAuthMount    = "admin-oidc"
	AdminRole         = "admin"
	AdminPolicyName   = "namespace-admin"
	adminDescription  = "Wyrwood namespace admin OIDC"
	adminPolicyMarker = "# Managed by Wyrwood openbao-admin"
)

// AdminSettings contains only the public inputs for namespace secret access.
type AdminSettings struct {
	Issuer, ClientID, GroupsClaim, RedirectURL string
	KVMounts                                   []string
	TokenTTL, TokenMaxTTL                      time.Duration
}

// NewAdminClient uses only the explicit provisioning identity and requires
// TLS except on loopback. No controller AppRole or ambient credential is used.
func NewAdminClient(endpoint Endpoint, token string) (*api.Client, error) {
	if !safeAdminURL(endpoint.Address) || !adminPath(endpoint.Namespace) || endpoint.Namespace == "root" || token == "" {
		return nil, &Error{Category: CategoryInvalid}
	}
	client, err := NewClient(endpoint)
	if err != nil {
		return nil, err
	}
	client.SetToken(token)
	// Redirects could forward the explicit namespace/token to another server.
	client.SetCheckRedirect(func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse })
	return client, nil
}

func safeAdminURL(value string) bool {
	u, err := url.Parse(value)
	if err != nil || !u.IsAbs() || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(value, "#") {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	ip := net.ParseIP(u.Hostname())
	return u.Scheme == "http" && (strings.EqualFold(u.Hostname(), "localhost") || (ip != nil && ip.IsLoopback()))
}

func adminPath(value string) bool {
	if value == "" {
		return false
	}
	for _, part := range strings.Split(value, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
		for _, c := range part {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
				return false
			}
		}
	}
	return true
}

// AdminPolicy generates only the approved KV v2 and self-session ACLs.
func AdminPolicy(mounts []string) (string, error) {
	if len(mounts) == 0 {
		return "", &Error{Category: CategoryInvalid}
	}
	sorted := slices.Clone(mounts)
	slices.Sort(sorted)
	var policy strings.Builder
	policy.WriteString(adminPolicyMarker + "\n")
	for i, mount := range sorted {
		first, _, _ := strings.Cut(mount, "/")
		if !adminPath(mount) || slices.Contains([]string{"sys", "auth", "identity", "cubbyhole"}, first) || (i > 0 && mount == sorted[i-1]) {
			return "", &Error{Category: CategoryInvalid}
		}
		for _, grant := range []struct{ path, caps string }{
			{"config", `"read"`},
			{"data/*", `"create", "read", "update", "delete"`},
			{"metadata", `"list"`},
			{"metadata/*", `"create", "read", "update", "delete", "list"`},
			{"delete/*", `"update"`}, {"undelete/*", `"update"`}, {"destroy/*", `"update"`},
		} {
			fmt.Fprintf(&policy, "path %q { capabilities = [%s] }\n", mount+"/"+grant.path, grant.caps)
		}
	}
	policy.WriteString(`path "auth/token/lookup-self" { capabilities = ["read"] }
path "auth/token/renew-self" { capabilities = ["update"] }
path "auth/token/revoke-self" { capabilities = ["update"] }
path "sys/capabilities-self" { capabilities = ["update"] }
path "sys/internal/ui/resultant-acl" { capabilities = ["read"] }
`)
	return policy.String(), nil
}

// Validate checks the public OIDC values and token durations.
func (settings AdminSettings) Validate() error {
	if !safeAdminURL(settings.Issuer) || !safeAdminURL(settings.RedirectURL) || !strings.HasSuffix(settings.RedirectURL, "/auth/"+AdminAuthMount+"/oidc/callback") ||
		settings.ClientID == "" || settings.GroupsClaim == "" || strings.ContainsAny(settings.ClientID+settings.GroupsClaim, "\r\n\x00") ||
		settings.TokenTTL < time.Second || settings.TokenMaxTTL < settings.TokenTTL || settings.TokenTTL%time.Second != 0 || settings.TokenMaxTTL%time.Second != 0 {
		return &Error{Category: CategoryInvalid}
	}
	return nil
}

func (settings AdminSettings) role() map[string]any {
	return map[string]any{
		"role_type": "oidc", "user_claim": "sub", "groups_claim": settings.GroupsClaim,
		"bound_claims_type": "string", "bound_claims": map[string]any{settings.GroupsClaim: []string{"wyrwood_admins"}},
		"bound_audiences": []string{settings.ClientID}, "oidc_scopes": []string{"profile", "email", "groups"},
		"token_policies": []string{AdminPolicyName}, "token_no_default_policy": true, "token_type": "service",
		"token_ttl": int64(settings.TokenTTL / time.Second), "token_max_ttl": int64(settings.TokenMaxTTL / time.Second),
		"token_explicit_max_ttl": int64(settings.TokenMaxTTL / time.Second), "token_period": 0, "token_num_uses": 0,
		"verbose_oidc_logging": false, "allowed_redirect_uris": []string{settings.RedirectURL},
	}
}
