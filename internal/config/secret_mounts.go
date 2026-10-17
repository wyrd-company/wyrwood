// ---
// relationships:
//   implements: configuration
// ---

package config

import (
	"slices"
	"strings"
)

// SecretMount describes an expected secret engine inside the OpenBao namespace.
// It does not provision an engine or grant access to it.
type SecretMount struct {
	Path string `yaml:"path" json:"path"`
	Type string `yaml:"type" json:"type"`
}

const (
	SecretMountKVV2  = "kv-v2"
	SecretMountOther = "other"
)

// SecretEngineMounts returns a copy of the configured secret-engine catalog.
// Policy advisories and editor path pickers share this catalog.
func (openbao ControllerOpenBao) SecretEngineMounts() []SecretMount {
	return append([]SecretMount(nil), openbao.SecretMounts...)
}

func validateSecretMounts(mounts []SecretMount) error {
	seen := make(map[string]bool, len(mounts))
	for _, mount := range mounts {
		if !validMount(mount.Path) || mount.Path == "." || strings.Contains(mount.Path, "/") {
			return invalid("openbao.secret-mounts paths must be plain mount names without slashes")
		}
		// OpenBao cannot mount secret engines at these reserved system roots.
		if slices.Contains([]string{"sys", "auth", "identity", "cubbyhole", "audit"}, mount.Path) {
			return invalid("openbao.secret-mounts paths must not use OpenBao reserved names")
		}
		if seen[mount.Path] {
			return invalid("openbao.secret-mounts paths must be unique")
		}
		if mount.Type != SecretMountKVV2 && mount.Type != SecretMountOther {
			return invalid("openbao.secret-mounts type must be kv-v2 or other")
		}
		seen[mount.Path] = true
	}
	return nil
}
