// ---
// relationships:
//   implements: web-interface
//   uses: operational-events
// ---

package web

import (
	"net/url"
	"slices"
	"strings"

	"github.com/wyrd-company/wyrwood/internal/controller"
	"github.com/wyrd-company/wyrwood/internal/controller/store"
	"github.com/wyrd-company/wyrwood/internal/events"
	operatorclient "github.com/wyrd-company/wyrwood/operator"
)

// grantChange is the old and new grant of one operator key grant edit, as the
// Events screen shows it.
type grantChange struct {
	Fingerprint string
	// EditURL opens the key's grant editor while the key is approved.
	EditURL string
	// Complete is whether every event of the edit is in the history. Rows is
	// empty when it is not, since the entries that are left do not say what
	// the grant was.
	Complete bool
	Rows     []grantChangeRow
}

type grantChangeRow struct {
	Name    string
	Before  string
	After   string
	Changed bool
}

// grantEdit gathers the events of one edit. The edit's first and last events
// name no entry, and each event between them holds one entry of the grant
// before the edit, after it, or both.
type grantEdit struct {
	row              int
	fingerprint      string
	agents, policies [2][]string
	actions          [2][]string
	// bounds counts the events that name no entry. An edit is whole when both
	// are in the history: retention drops the oldest events, and an edit cut
	// short leaves out the newest.
	bounds int
}

func (edit *grantEdit) add(event events.Event) {
	if event.Agent == "" && event.NewAgent == "" && event.Policy == "" && event.NewPolicy == "" &&
		event.Action == events.ActionNone && event.NewAction == events.ActionNone {
		edit.bounds++
		return
	}
	gather := func(list *[2][]string, before, after string) {
		if before != "" {
			list[0] = append(list[0], before)
		}
		if after != "" {
			list[1] = append(list[1], after)
		}
	}
	gather(&edit.agents, event.Agent, event.NewAgent)
	gather(&edit.policies, event.Policy, event.NewPolicy)
	gather(&edit.actions, string(event.Action), string(event.NewAction))
}

func (edit *grantEdit) change(keys []store.OperatorKey) *grantChange {
	change := &grantChange{Fingerprint: edit.fingerprint, Complete: edit.bounds >= 2}
	for _, key := range keys {
		if key.Fingerprint == edit.fingerprint && key.State == store.OperatorKeyApproved {
			change.EditURL = "/operator-keys/grant?" + url.Values{"fingerprint": {key.Fingerprint}}.Encode()
		}
	}
	if !change.Complete {
		return change
	}
	names := func(list []string) string {
		list = slices.Compact(slices.Sorted(slices.Values(list)))
		switch {
		case len(list) == 0:
			return "None"
		case slices.Equal(list, []string{operatorclient.AllNames}):
			return "All"
		}
		return strings.Join(list, ", ")
	}
	row := func(name, before, after string) grantChangeRow {
		return grantChangeRow{Name: name, Before: before, After: after, Changed: before != after}
	}
	change.Rows = append(change.Rows,
		row("Agents", names(edit.agents[0]), names(edit.agents[1])),
		row("Policies", names(edit.policies[0]), names(edit.policies[1])))
	for _, action := range []struct {
		action operatorclient.Action
		name   string
	}{{operatorclient.ActionRead, "Read"}, {operatorclient.ActionBind, "Bind"}, {operatorclient.ActionPolicyWrite, "Policy write"}} {
		allowed := func(list []string) string {
			if slices.Contains(list, string(action.action)) {
				return "Allowed"
			}
			return "Denied"
		}
		change.Rows = append(change.Rows, row(action.name, allowed(edit.actions[0]), allowed(edit.actions[1])))
	}
	return change
}

// keySubject names an operator key as events do, by its label, or by its
// fingerprint when the controller no longer has the key.
func keySubject(keys []store.OperatorKey, fingerprint string) string {
	for _, key := range keys {
		if key.Fingerprint == fingerprint {
			return controller.OperatorSubject(key.Label)
		}
	}
	return fingerprint
}
