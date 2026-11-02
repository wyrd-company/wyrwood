// ---
// relationships:
//   verifies: web-interface
// ---

package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/wyrd-company/wyrwood/internal/events"
	"github.com/wyrd-company/wyrwood/internal/openbao/baotest"
)

// A real denial: the controller's policy loses delete on managed policies.
func TestPolicyDeleteKeepsThePolicyAndOffersARetryWhenOpenBaoRefuses(t *testing.T) {
	fixture := newListFixture(t)
	saved := fixture.published(t, freePolicy)
	root := fixture.harness.bao.Root.Sys()
	withoutDelete := strings.Replace(baotest.ControllerPolicy,
		`path "sys/policies/acl/wyrwood-*" { capabilities = ["create", "read", "update", "delete", "list"] }`,
		`path "sys/policies/acl/wyrwood-*" { capabilities = ["create", "read", "update", "list"] }`, 1)
	if withoutDelete == baotest.ControllerPolicy {
		t.Fatal("the fault did not change the controller's policy")
	}
	if err := root.PutPolicy(baotest.ControllerName, withoutDelete); err != nil {
		t.Fatal(err)
	}
	failed := fixture.deletePolicy(t, freePolicy)
	if failed.status != http.StatusUnprocessableEntity || failed.page != policyDeletePageName || !strings.Contains(failed.data.Problem, "OpenBao could not delete") {
		t.Fatalf("failed = %d %s", failed.status, failed.raw)
	}
	if failed.data.Action != policyDeletePath+freePolicy || failed.data.Button == "" {
		t.Fatalf("no retry: %#v", failed.data.confirmPage)
	}
	if !fixture.stored(t, freePolicy) || fixture.acl(t, freePolicyACL) != saved.PublishedHCL() {
		t.Fatal("a failed delete changed the policy")
	}
	event := fixture.lastDeleteEvent(t)
	if event.Outcome != events.OutcomeDenied || event.ErrorCode != events.ErrorOpenBaoDenied {
		t.Fatalf("event = %#v", event)
	}
	if err := root.PutPolicy(baotest.ControllerName, baotest.ControllerPolicy); err != nil {
		t.Fatal(err)
	}
	if done := fixture.deletePolicy(t, freePolicy); done.status != http.StatusSeeOther {
		t.Fatalf("retry = %d %s", done.status, done.raw)
	}
	if fixture.stored(t, freePolicy) || fixture.acl(t, freePolicyACL) != "" {
		t.Fatal("the retry did not delete")
	}
}

// A failed read must not read as a policy with no blockers.
func TestPolicyDeleteAnswersAnErrorWhenAReadFails(t *testing.T) {
	fixture := newListFixture(t)
	database := openStore(t, fixture.harness)
	fixture.published(t, freePolicy)
	inventoryFault("host-a").during(t, database, func() {
		screen := fixture.confirmDelete(t, boundPolicy)
		if screen.status != http.StatusInternalServerError || !strings.Contains(string(screen.raw), bindingsUnreadable) {
			t.Fatalf("confirm = %d %s", screen.status, screen.raw)
		}
		refused := fixture.deletePolicy(t, boundPolicy)
		if refused.status != http.StatusInternalServerError || !strings.Contains(string(refused.raw), bindingsUnreadable) || !strings.Contains(string(refused.raw), "bindings still select") {
			t.Fatalf("refused = %d %s", refused.status, refused.raw)
		}
	})
	if !fixture.stored(t, boundPolicy) {
		t.Fatal("a refused delete removed the policy")
	}
	policyFault := storeFault{name: "policies", apply: `ALTER TABLE policies RENAME TO policies_unavailable`, restore: `ALTER TABLE policies_unavailable RENAME TO policies`}
	policyFault.during(t, database, func() {
		screen := fixture.confirmDelete(t, freePolicy)
		if screen.status != http.StatusInternalServerError || screen.page != "" {
			t.Fatalf("confirm = %d %s", screen.status, screen.raw)
		}
		failed := fixture.deletePolicy(t, freePolicy)
		if failed.status != http.StatusInternalServerError || !strings.Contains(string(failed.raw), "could not be read") {
			t.Fatalf("delete = %d %s", failed.status, failed.raw)
		}
	})
	if !fixture.stored(t, freePolicy) || fixture.acl(t, freePolicyACL) == "" {
		t.Fatal("a failed read changed the policy")
	}
}

func TestPolicyDeleteRoutesRequireASession(t *testing.T) {
	fixture := newListFixture(t)
	fixture.published(t, freePolicy)
	anonymous := noRedirects(browser(t))
	target := fixture.harness.site.URL + policyDeletePath + freePolicy
	response, err := anonymous.Get(target)
	confirm := readDelete(t, response, err)
	if confirm.status != http.StatusSeeOther || confirm.location != "/sign-in" || confirm.page != "" {
		t.Fatalf("anonymous confirm = %d %q", confirm.status, confirm.location)
	}
	response, err = anonymous.PostForm(target, url.Values{"csrf": {fixture.deleteToken(t)}})
	deleted := readDelete(t, response, err)
	if deleted.status != http.StatusSeeOther || deleted.location != "/sign-in" {
		t.Fatalf("anonymous delete = %d %q", deleted.status, deleted.location)
	}
	if !fixture.stored(t, freePolicy) || fixture.acl(t, freePolicyACL) == "" {
		t.Fatal("an anonymous request deleted the policy")
	}
}

func TestPolicyDeleteRequiresTheAntiForgeryToken(t *testing.T) {
	fixture := newListFixture(t)
	fixture.published(t, freePolicy)
	target := fixture.harness.site.URL + policyDeletePath + freePolicy
	for label, form := range map[string]url.Values{"absent": {}, "wrong": {"csrf": {"not-the-token"}}} {
		response, err := noRedirects(fixture.client).PostForm(target, form)
		refused := readDelete(t, response, err)
		if refused.status != http.StatusForbidden {
			t.Fatalf("%s token = %d", label, refused.status)
		}
		if !fixture.stored(t, freePolicy) || fixture.acl(t, freePolicyACL) == "" {
			t.Fatalf("%s token deleted the policy", label)
		}
	}
	if done := fixture.deletePolicy(t, freePolicy); done.status != http.StatusSeeOther {
		t.Fatalf("valid token = %d %s", done.status, done.raw)
	}
}

// GET and the HEAD it serves are read-only.
func TestPolicyDeleteConfirmIsReadOnly(t *testing.T) {
	fixture := newListFixture(t)
	fixture.published(t, freePolicy)
	target := fixture.harness.site.URL + policyDeletePath + freePolicy
	response, err := noRedirects(fixture.client).Head(target)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("HEAD = %d", response.StatusCode)
	}
	if !fixture.stored(t, freePolicy) || fixture.acl(t, freePolicyACL) == "" {
		t.Fatal("a read deleted the policy")
	}
	for _, event := range fixture.harness.controller.Events().Recent(1000) {
		if event.Operation == events.OperationPolicyDeleted {
			t.Fatalf("a read recorded %#v", event)
		}
	}
}

// The page data has no token accessor.
func TestPolicyDeleteRefusalExposesNoCredential(t *testing.T) {
	fixture := newListFixture(t)
	const accessor = "sentinel-accessor-value"
	if err := fixture.harness.controller.Store().SaveTokenAccessor(fixture.ctx, "b-a-sample", accessor, fixture.now); err != nil {
		t.Fatal(err)
	}
	screen := fixture.confirmDelete(t, boundPolicy)
	if strings.Contains(string(screen.raw), accessor) {
		t.Fatal("the page exposes a token accessor")
	}
}
