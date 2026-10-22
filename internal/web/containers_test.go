// ---
// relationships:
//   verifies: web-interface
// ---

package web

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/wyrd-company/wyrwood/internal/controller/store"
	"github.com/wyrd-company/wyrwood/internal/policy"
	"github.com/wyrd-company/wyrwood/internal/protocol"
	"github.com/wyrd-company/wyrwood/internal/web/oidctest"
)

func TestAllContainersInventoryFilteringSortingAndIdentity(t *testing.T) {
	h := startHarness(t, time.Hour)
	client := browser(t)
	h.signIn(t, client, operator, oidctest.TamperNone)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	for _, agent := range []struct {
		name  string
		state store.AgentState
	}{
		{"host-a", store.AgentApproved}, {"host-b", store.AgentApproved}, {"pending", store.AgentPending}, {"rejected", store.AgentRejected}, {"empty", store.AgentApproved},
	} {
		if _, err := h.controller.Store().RecordKey(ctx, agent.name, agent.name, "ssh-ed25519 AAAA", now); err != nil {
			t.Fatal(err)
		}
		if agent.state != store.AgentPending {
			if _, err := h.controller.Store().DecideAgent(ctx, agent.name, agent.state, "operator", now); err != nil {
				t.Fatal(err)
			}
		}
		containers := []protocol.Container{{ID: "shared-id", Name: "sample", Image: "busybox:latest", State: protocol.StateRunning, ConsumerDirectory: "/srv/sample/" + agent.name, Keys: []protocol.Key{{Kind: protocol.KeyName, Value: "sample"}}}}
		if agent.name == "host-a" {
			containers = append(containers, protocol.Container{ID: "other-id", Name: "zebra", Image: "alpine:latest", State: protocol.StateExited})
		}
		if agent.name == "empty" {
			containers = nil
		}
		if err := h.controller.Store().SaveInventory(ctx, agent.name, agent.name, containers, now); err != nil {
			t.Fatal(err)
		}
	}
	document := policy.New("sample-policy", `path "kv/*" { capabilities = ["read"] }`)
	if _, err := h.controller.Store().SavePolicy(ctx, document, "operator", now); err != nil {
		t.Fatal(err)
	}
	binding := store.Binding{ID: "binding-b", Agent: "host-b", Key: protocol.Key{Kind: protocol.KeyName, Value: "sample"}, Policies: []string{"sample-policy"}, Revision: 1, Applied: true, Effective: policy.Effective{Contract: policy.Contract{MountTarget: "/opt/sample"}}, CreatedAt: now}
	if err := h.controller.Store().CreateBinding(ctx, binding); err != nil {
		t.Fatal(err)
	}
	if err := h.controller.Store().SaveContractResult(ctx, protocol.ContractResult{Binding: binding.ID, Outcome: protocol.OutcomeConforming}, now); err != nil {
		t.Fatal(err)
	}
	load := func(query string) containersPage {
		t.Helper()
		response, err := client.Get(h.site.URL + "/containers" + query)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != http.StatusOK {
			t.Fatalf("status = %d", response.StatusCode)
		}
		match := pageDataPattern.FindSubmatch(body)
		if match == nil {
			t.Fatalf("no containers page: %s", body)
		}
		var payload struct {
			Page string
			Data containersPage
		}
		if err := json.Unmarshal(match[1], &payload); err != nil {
			t.Fatal(err)
		}
		if payload.Page != "containers" {
			t.Fatalf("page = %s", payload.Page)
		}
		return payload.Data
	}
	identities := func(page containersPage) []string {
		result := []string{}
		for _, row := range page.Rows {
			result = append(result, row.Agent+"/"+row.ID)
		}
		return result
	}
	t.Run("default includes every approved last report without selection", func(t *testing.T) {
		page := load("")
		if got, want := identities(page), []string{"host-a/shared-id", "host-b/shared-id", "host-a/other-id"}; !reflect.DeepEqual(got, want) {
			t.Fatalf("rows = %v, want %v", got, want)
		}
		if len(page.Agents) != 3 || page.FilterAgent != "" || page.Sort != "name" || page.Order != "asc" {
			t.Fatalf("defaults = %#v", page)
		}
		for _, row := range page.Rows {
			if row.Connected || !row.LastReport.Equal(now) {
				t.Fatalf("last report = %#v", row)
			}
		}
	})
	for _, test := range []struct {
		query string
		want  []string
	}{
		{"?filter-agent=host-b", []string{"host-b/shared-id"}},
		{"?agent=host-b", []string{"host-b/shared-id"}},
		{"?filter-agent=empty", []string{}},
		{"?filter-agent=missing", []string{}},
		{"?q=%20SAMPLE-POLICY%20", []string{"host-b/shared-id"}},
		{"?q=EXITED", []string{"host-a/other-id"}},
		{"?q=alpine", []string{"host-a/other-id"}},
		{"?q=Conforms&filter-agent=host-a", []string{}},
		{"?q=missing", []string{}},
		{"?sort=name&order=desc", []string{"host-a/other-id", "host-b/shared-id", "host-a/shared-id"}},
		{"?sort=agent&order=desc", []string{"host-b/shared-id", "host-a/shared-id", "host-a/other-id"}},
		{"?sort=image", []string{"host-a/other-id", "host-a/shared-id", "host-b/shared-id"}},
		{"?sort=state", []string{"host-b/shared-id", "host-a/other-id", "host-a/shared-id"}},
		{"?sort=unknown&order=unknown", []string{"host-a/shared-id", "host-b/shared-id", "host-a/other-id"}},
	} {
		t.Run(test.query, func(t *testing.T) {
			if got := identities(load(test.query)); !reflect.DeepEqual(got, test.want) {
				t.Fatalf("rows = %v, want %v", got, test.want)
			}
		})
	}
	t.Run("selection uses both agent and container and retains setup", func(t *testing.T) {
		page := load("?agent=host-b&container=shared-id&filter-agent=&q=" + url.QueryEscape("busybox"))
		if len(page.Rows) != 2 || page.Selected == nil || page.Selected.Agent != "host-b" || page.Agent != "host-b" || page.Selected.BindingID != "binding-b" || page.Selected.Setup == nil || page.Selected.Setup.Source != "/srv/sample/host-b" {
			t.Fatalf("selection = %#v", page)
		}
		if page.Rows[0].Bound {
			t.Fatal("binding leaked into another agent's row")
		}
		// Filtering does not change the owner of an explicitly selected detail form.
		page = load("?agent=host-b&container=shared-id&filter-agent=host-a")
		if len(page.Rows) != 2 || page.Selected == nil || page.Selected.Agent != "host-b" {
			t.Fatalf("filtered selection = %#v", page)
		}
		for _, query := range []string{"?container=shared-id", "?agent=missing&container=shared-id", "?agent=pending&container=shared-id", "?agent=host-b&container=missing"} {
			if page := load(query); page.Selected != nil {
				t.Fatalf("ambiguous or unavailable selection: %s %#v", query, page.Selected)
			}
		}
	})
}
