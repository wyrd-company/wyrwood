// ---
// relationships:
//   implements: policy
//   uses: configuration
// ---

package controller

import "github.com/wyrd-company/wyrwood/internal/policy"

// PolicyWarnings provides advisory HCL checks without publishing or validating
// the policy. OpenBao remains authoritative when the operator saves it.
func (controller *Controller) PolicyWarnings(document string) []string {
	configuration := controller.Configuration().OpenBao
	mounts := []string{"auth/" + configuration.AppRoleMount, configuration.TransitMount, configuration.SSHMount}
	for _, mount := range configuration.SecretEngineMounts() {
		mounts = append(mounts, mount.Path)
	}
	warnings := policy.Warnings(document)
	return append(warnings, policy.MountWarnings(document, mounts)...)
}
