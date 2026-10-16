// ---
// relationships:
//   implements: openbao-admin-access
// ---

package openbao

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/openbao/openbao/api/v2"
)

// AdminError reports only categorical stage and possible partial setup. It
// never retains an upstream error, request body, token, or client secret.
type AdminError struct {
	Stage    string
	Category Category
	Partial  bool
}

func (err *AdminError) Error() string {
	return "openbao admin " + err.Stage + ": " + string(err.Category)
}

func adminFailure(stage string, partial bool, err error) error {
	return &AdminError{Stage: stage, Category: CategoryOf(categorize(err)), Partial: partial}
}

// ConfigureAdmin provisions the dedicated OIDC mount with secret-only access.
// The caller's client carries the separate namespace provisioning identity.
func ConfigureAdmin(ctx context.Context, client *api.Client, settings AdminSettings, clientSecret string) error {
	if err := settings.Validate(); err != nil {
		return adminFailure("preflight", false, err)
	}
	if clientSecret == "" || strings.ContainsAny(clientSecret, "\r\n\x00") {
		return adminFailure("preflight", false, &Error{Category: CategoryInvalid})
	}
	policy, err := AdminPolicy(settings.KVMounts)
	if err != nil {
		return adminFailure("preflight", false, err)
	}
	if err := checkProvisioner(ctx, client, false); err != nil {
		return adminFailure("preflight", false, err)
	}
	mounts, err := client.Sys().ListMountsWithContext(ctx)
	if err != nil {
		return adminFailure("preflight", false, err)
	}
	for _, name := range settings.KVMounts {
		mount := mounts[name+"/"]
		if mount == nil || mount.Type != "kv" || mount.Options["version"] != "2" {
			return adminFailure("preflight", false, &Error{Category: CategoryInvalid})
		}
	}
	exists, _, err := ownedAdminResources(ctx, client)
	if err != nil {
		return adminFailure("ownership", false, err)
	}
	if err := client.Sys().PutPolicyWithContext(ctx, AdminPolicyName, policy); err != nil {
		return adminFailure("policy", true, err)
	}
	if !exists {
		if err := client.Sys().EnableAuthWithOptionsWithContext(ctx, AdminAuthMount, &api.EnableAuthOptions{
			Type: "oidc", Description: adminDescription, Config: api.MountConfigInput{ListingVisibility: "unauth"},
		}); err != nil {
			return adminFailure("mount", true, err)
		}
	} else {
		if _, err := client.Logical().WriteWithContext(ctx, "sys/auth/"+AdminAuthMount+"/tune", map[string]any{"listing_visibility": "unauth"}); err != nil {
			return adminFailure("mount", true, err)
		}
	}
	_, err = client.Logical().WriteWithContext(ctx, "auth/"+AdminAuthMount+"/config", map[string]any{
		"oidc_discovery_url": settings.Issuer, "bound_issuer": settings.Issuer,
		"oidc_client_id": settings.ClientID, "oidc_client_secret": clientSecret,
		"default_role": AdminRole, "namespace_in_state": true,
		"oidc_response_types": []string{"code"}, "oidc_response_mode": "query",
	})
	if err != nil {
		return adminFailure("config", true, err)
	}
	if _, err := client.Logical().WriteWithContext(ctx, "auth/"+AdminAuthMount+"/role/"+AdminRole, settings.role()); err != nil {
		return adminFailure("role", true, err)
	}
	return nil
}

// RemoveAdmin revokes sessions by disabling the owned mount before deleting
// the owned policy. It preserves engines, values and controller resources.
func RemoveAdmin(ctx context.Context, client *api.Client) error {
	if err := checkProvisioner(ctx, client, true); err != nil {
		return adminFailure("preflight", false, err)
	}
	exists, policyExists, err := ownedAdminResources(ctx, client)
	if err != nil {
		return adminFailure("ownership", false, err)
	}
	if exists {
		if err := client.Sys().DisableAuthWithContext(ctx, AdminAuthMount); err != nil {
			return adminFailure("disable", true, err)
		}
	}
	if policyExists {
		if err := client.Sys().DeletePolicyWithContext(ctx, AdminPolicyName); err != nil {
			return adminFailure("delete-policy", true, err)
		}
	}
	return nil
}

func ownedAdminResources(ctx context.Context, client *api.Client) (bool, bool, error) {
	policy, err := client.Sys().GetPolicyWithContext(ctx, AdminPolicyName)
	if err != nil {
		return false, false, err
	}
	if policy != "" && !strings.HasPrefix(policy, adminPolicyMarker+"\n") {
		return false, false, &Error{Category: CategoryInvalid}
	}
	auth, err := client.Logical().ReadWithContext(ctx, "sys/auth/"+AdminAuthMount)
	var response *api.ResponseError
	if errors.As(err, &response) && response.StatusCode == http.StatusBadRequest && len(response.Errors) == 1 && response.Errors[0] == "No auth engine at "+AdminAuthMount+"/" {
		return false, policy != "", nil
	}
	if err != nil {
		return false, false, err
	}
	if auth == nil {
		return false, policy != "", nil
	}
	if auth.Data["type"] != "oidc" || auth.Data["description"] != adminDescription {
		return false, false, &Error{Category: CategoryInvalid}
	}
	roles, err := listNames(ctx, client, "auth/"+AdminAuthMount+"/role")
	if err != nil {
		return false, false, err
	}
	for _, role := range roles {
		if role != AdminRole {
			return false, false, &Error{Category: CategoryInvalid}
		}
	}
	return true, policy != "", nil
}

func checkProvisioner(ctx context.Context, client *api.Client, remove bool) error {
	if !adminPath(client.Namespace()) || client.Namespace() == "root" || client.Token() == "" {
		return &Error{Category: CategoryInvalid}
	}
	required := map[string][]string{
		"sys/auth/" + AdminAuthMount:          {"read", "delete", "sudo"},
		"auth/" + AdminAuthMount + "/role":    {"list"},
		"sys/policies/acl/" + AdminPolicyName: {"read", "delete"},
	}
	if !remove {
		required["sys/mounts"] = []string{"read"}
		required["sys/auth/"+AdminAuthMount] = []string{"read", "update", "sudo"}
		required["sys/auth/"+AdminAuthMount+"/tune"] = []string{"read", "update", "sudo"}
		required["auth/"+AdminAuthMount+"/config"] = []string{"read", "update"}
		required["auth/"+AdminAuthMount+"/role/"+AdminRole] = []string{"read", "update"}
		required["sys/policies/acl/"+AdminPolicyName] = []string{"read", "create", "update"}
	}
	for path, needed := range required {
		caps, err := client.Sys().CapabilitiesSelfWithContext(ctx, path)
		if err != nil {
			return err
		}
		if slices.Contains(caps, "root") {
			continue
		}
		for _, cap := range needed {
			if !slices.Contains(caps, cap) {
				return &Error{Category: CategoryDenied}
			}
		}
	}
	return nil
}
