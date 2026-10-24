// ---
// relationships:
//   verifies: controller
//   mitigates: controller-token-blast-radius
// ---

package openbao

import (
	"context"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/openbao/openbao/api/v2"
	"github.com/wyrd-company/wyrwood/internal/openbao/baotest"
)

func TestKVBrowserListsOnlyConfiguredNamespacedMetadata(t *testing.T) {
	ctx := context.Background()
	server, manager := testManager(t)
	server.WriteKV(t, "folder/nested", map[string]any{"value": "sample-secret-value"})
	server.WriteKV(t, "sample", map[string]any{"value": "sample-secret-value"})
	names, err := manager.ListKVPaths(ctx, "kv", "")
	if err != nil || !reflect.DeepEqual(names, []string{"folder/", "sample"}) {
		t.Fatalf("root names = %v, %v", names, err)
	}
	names, err = manager.ListKVPaths(ctx, "kv", "folder/")
	if err != nil || !reflect.DeepEqual(names, []string{"nested"}) {
		t.Fatalf("nested names = %v, %v", names, err)
	}
	names, err = manager.ListKVPaths(ctx, "kv", "empty/")
	if err != nil || len(names) != 0 {
		t.Fatalf("empty names = %v, %v", names, err)
	}
	for _, sample := range []struct{ mount, prefix string }{
		{"other", ""}, {"transit", ""}, {"sys/mounts", ""}, {"kv/../sys", ""},
		{"kv", "../data/"}, {"kv", "/"}, {"kv", "folder/../../data/"}, {"kv", "folder//"},
		{"kv", "folder/./"}, {"kv", "%2e%2e/data/"}, {"kv", "folder?list=true/"},
		{"kv", "folder#fragment/"}, {"kv", "folder\\../"}, {"kv", "folder\n/"}, {"kv", "folder"},
	} {
		if _, err := manager.ListKVPaths(ctx, sample.mount, sample.prefix); CategoryOf(err) != CategoryInvalid {
			t.Errorf("ListKVPaths(%q, %q) = %v, want invalid", sample.mount, sample.prefix, err)
		}
	}
	// Assert real controller credential capabilities, including LIST boundaries.
	client, err := manager.authorized(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"kv/data/sample", "kv/metadata/sample", "sys/mounts"} {
		if _, err := client.Logical().ReadWithContext(ctx, target); CategoryOf(categorize(err)) != CategoryDenied {
			t.Errorf("controller read %s = %v, want denied", target, err)
		}
	}
	if _, err := client.Logical().WriteWithContext(ctx, "kv/data/sample", map[string]any{"data": map[string]any{"value": "overwrite"}}); CategoryOf(categorize(err)) != CategoryDenied {
		t.Errorf("controller KV write = %v, want denied", err)
	}
	if _, err := client.Logical().DeleteWithContext(ctx, "kv/metadata/sample"); CategoryOf(categorize(err)) != CategoryDenied {
		t.Errorf("controller KV delete = %v, want denied", err)
	}
	if err := server.Root.Sys().MountWithContext(ctx, "other", &api.MountInput{Type: "kv", Options: map[string]string{"version": "2"}}); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"other/metadata", "sys/mounts", "kv/data"} {
		if _, err := client.Logical().ListWithContext(ctx, target); CategoryOf(categorize(err)) != CategoryDenied {
			t.Errorf("controller LIST %s = %v, want denied", target, err)
		}
	}
	outside, err := withToken(server.TopLevel, client.Token())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := outside.Logical().ListWithContext(ctx, "secret/metadata"); err == nil {
		t.Fatal("controller listed outside its namespace")
	}
	// Even a directly constructed manager cannot browse the root namespace.
	rootClient, err := NewClient(Endpoint{Address: server.Address})
	if err != nil {
		t.Fatal(err)
	}
	rootManager := NewManager(rootClient, Mounts{KV: []string{"kv"}}, "", nil)
	rootManager.token = NewToken(baotest.RootToken, time.Hour)
	if _, err := rootManager.ListKVPaths(ctx, "kv", ""); CategoryOf(err) != CategoryInvalid {
		t.Fatalf("root manager LIST = %v", err)
	}
}

func TestDocumentedControllerPolicyMatchesHarness(t *testing.T) {
	data, err := os.ReadFile("../../docs/user/configuration.md")
	if err != nil {
		t.Fatal(err)
	}
	_, rest, ok := strings.Cut(string(data), "The controller's policy,")
	if !ok {
		t.Fatal("controller policy heading missing")
	}
	_, rest, ok = strings.Cut(rest, "```hcl\n")
	if !ok {
		t.Fatal("controller policy missing")
	}
	document, _, ok := strings.Cut(rest, "```")
	if !ok {
		t.Fatal("controller policy block unclosed")
	}
	if strings.Join(strings.Fields(document), " ") != strings.Join(strings.Fields(baotest.ControllerPolicy), " ") {
		t.Fatal("documented controller policy differs from the real test harness")
	}
}
