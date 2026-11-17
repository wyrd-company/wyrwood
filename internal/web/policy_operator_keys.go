// ---
// relationships:
//   implements: web-interface
//   uses: authenticate-operator-keys-over-ssh
// ---

package web

import (
	"context"
	"net/url"
	"slices"

	"github.com/wyrd-company/wyrwood/internal/controller/store"
	operatorclient "github.com/wyrd-company/wyrwood/operator"
)

// policyOperatorKey is an approved operator key on a policy's Operator keys
// tab. Checking it gives the key the policy, and clearing it takes the policy
// away; the key's actions stay as they are.
type policyOperatorKey struct {
	Label       string
	Fingerprint string
	Actions     []operatorclient.Action
	// AllPolicies marks a key whose grant holds every policy. The tab shows it
	// checked and does not change it.
	AllPolicies bool
	// Held is whether the key's grant named the policy when the screen was
	// opened, and Selected whether its box is checked. The form posts both,
	// so that a save changes only the keys whose boxes changed.
	Held     bool
	Selected bool
}

// fillPolicyOperatorKeys lists the approved operator keys for the policy name,
// which is empty for a new policy. form is a save that was refused, or nil: a
// key the form listed keeps the boxes it posted.
func (server *Server) fillPolicyOperatorKeys(ctx context.Context, page *policyPage, name string, form url.Values) error {
	keys, err := server.controller.Store().OperatorKeys(ctx)
	if err != nil {
		return err
	}
	page.OperatorKeys = []policyOperatorKey{}
	for _, key := range keys {
		if key.State != store.OperatorKeyApproved {
			continue
		}
		row := policyOperatorKey{Label: key.Label, Fingerprint: key.Fingerprint, Actions: key.Grant.Actions,
			AllPolicies: slices.Equal(key.Grant.Policies, []string{operatorclient.AllNames})}
		switch {
		case row.AllPolicies:
			row.Selected = true
		case form != nil && slices.Contains(form["operator-keys-listed"], key.Fingerprint):
			row.Held = slices.Contains(form["operator-keys-held"], key.Fingerprint)
			row.Selected = slices.Contains(form["operator-keys"], key.Fingerprint)
		default:
			row.Held = name != "" && slices.Contains(key.Grant.Policies, name)
			row.Selected = row.Held
		}
		page.OperatorKeys = append(page.OperatorKeys, row)
	}
	return nil
}

// policyKeyChanges returns the keys a policy form gives the policy to and the
// keys it takes the policy from: each listed key whose box is checked now and
// was not when the screen was opened, or the reverse. A key the form did not
// list is not changed.
func policyKeyChanges(form url.Values) (add, remove []string) {
	for _, fingerprint := range form["operator-keys-listed"] {
		checked := slices.Contains(form["operator-keys"], fingerprint)
		held := slices.Contains(form["operator-keys-held"], fingerprint)
		switch {
		case checked && !held:
			add = append(add, fingerprint)
		case held && !checked:
			remove = append(remove, fingerprint)
		}
	}
	return add, remove
}
