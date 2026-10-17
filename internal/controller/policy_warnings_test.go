// ---
// relationships:
//   verifies: policy
// ---

package controller

import (
	"fmt"
	"strings"
	"testing"

	"github.com/wyrd-company/wyrwood/internal/config"
	"github.com/wyrd-company/wyrwood/internal/policy"
)

func TestPolicyWarningsUseConfiguredMounts(t *testing.T) {
	c := &Controller{config: config.Controller{OpenBao: config.ControllerOpenBao{
		AppRoleMount: "sample-role", TransitMount: "sample-transit", SSHMount: "sample-ssh",
		SecretMounts: []config.SecretMount{{Path: "sample-data", Type: config.SecretMountKVV2}, {Path: "sample-certs", Type: config.SecretMountOther}},
	}}}
	for _, path := range []string{"auth/sample-role/role/*", "sample-transit/sign/+", "sample-ssh/sign/*", "sample-data/data/+/entry", "sample-certs/*"} {
		t.Run(path, func(t *testing.T) {
			document := policy.StarterHCL + fmt.Sprintf("path %q { capabilities = [\"read\"] }", path)
			if warnings := c.PolicyWarnings(document); len(warnings) != 0 {
				t.Fatalf("configured mount warnings = %v", warnings)
			}
		})
	}
	for _, path := range []string{"auth/approle/*", "transit/*", "ssh/*", "kv/*", "sys/*"} {
		t.Run(path, func(t *testing.T) {
			document := policy.StarterHCL + fmt.Sprintf("path %q { capabilities = [\"read\"] }", path)
			if warnings := c.PolicyWarnings(document); len(warnings) != 1 || !strings.Contains(warnings[0], "outside the configured mounts") {
				t.Fatalf("unconfigured mount warnings = %v", warnings)
			}
		})
	}
	if warnings := c.PolicyWarnings(`path "sys/*" { capabilities = ["read"] }`); len(warnings) != 2 || warnings[0] != policy.RenewalWarning {
		t.Fatalf("combined advisories = %v", warnings)
	}
}
