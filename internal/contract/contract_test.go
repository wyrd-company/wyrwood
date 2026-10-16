// ---
// relationships:
//   verifies: container-contract
// ---

package contract

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/wyrd-company/wyrwood/internal/engine"
	"github.com/wyrd-company/wyrwood/internal/policy"
	"github.com/wyrd-company/wyrwood/internal/protocol"
)

const consumerDirectory = "/run/wyrwood/containers/wyr-fixture"

func loadFixture(t *testing.T, name string) (engine.Container, map[string]any) {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	container, err := engine.ParseInspect(data)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	return container, raw
}

func groupContract() policy.Contract {
	contract := policy.DefaultContract()
	group := uint32(1000)
	contract.AccessGroup = &group
	contract.Enforcement = policy.EnforcementRecreate
	return contract
}

func TestCheckReportsEachFailedItem(t *testing.T) {
	container, _ := loadFixture(t, "inspect-running.json")
	contract := groupContract()
	failed := Check(container, contract, consumerDirectory, func(uint32) bool { return false })
	want := []protocol.FailedItem{protocol.FailedMount, protocol.FailedEnv, protocol.FailedAccessGroup}
	if !reflect.DeepEqual(failed, want) {
		t.Fatalf("Check() = %v, want %v", failed, want)
	}
	container.Mounts = append(container.Mounts, engine.Mount{Type: "bind", Source: consumerDirectory + "/", Destination: "/run/wyrwood"})
	container.Config.Env = append(container.Config.Env, "SSH_AUTH_SOCK=/run/wyrwood/ssh-agent.sock", "VAULT_ADDR=unix:///run/wyrwood/vault.sock")
	container.Config.Env[0] = "IGNORED=1"
	for index, entry := range container.Config.Env {
		if strings.HasPrefix(entry, "VAULT_ADDR=wrong") {
			container.Config.Env[index] = "UNRELATED=1"
		}
	}
	if failed := Check(container, contract, consumerDirectory, func(uint32) bool { return true }); len(failed) != 0 {
		t.Fatalf("Check(conforming) = %v", failed)
	}
}

func TestBuildCreateRequestPreservesEveryField(t *testing.T) {
	container, raw := loadFixture(t, "inspect-running.json")
	originalConfig := raw["Config"].(map[string]any)
	originalHost := raw["HostConfig"].(map[string]any)
	request, err := BuildCreateRequest(container, groupContract(), consumerDirectory, container.Image)
	if err != nil {
		t.Fatal(err)
	}
	if request.Name != "wyr-fixture" || !request.Running || request.Stop != 7 {
		t.Fatalf("request = %q running=%v stop=%d", request.Name, request.Running, request.Stop)
	}
	var body map[string]any
	if err := json.Unmarshal(request.Body, &body); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"Image", "Cmd", "Entrypoint", "WorkingDir", "User", "Labels", "Hostname", "ExposedPorts", "Volumes", "StopTimeout"} {
		if !reflect.DeepEqual(body[field], originalConfig[field]) {
			t.Errorf("Config.%s = %#v, want %#v", field, body[field], originalConfig[field])
		}
	}
	env := toStrings(body["Env"])
	for _, want := range []string{"KEEP=1", "SSH_AUTH_SOCK=/run/wyrwood/ssh-agent.sock", "VAULT_ADDR=unix:///run/wyrwood/vault.sock"} {
		if !contains(env, want) {
			t.Errorf("Env lacks %q: %v", want, env)
		}
	}
	if contains(env, "VAULT_ADDR=wrong") {
		t.Errorf("Env kept the replaced value: %v", env)
	}
	host := body["HostConfig"].(map[string]any)
	for _, field := range []string{"PortBindings", "RestartPolicy", "Memory", "NanoCpus", "NetworkMode", "LogConfig"} {
		if !reflect.DeepEqual(host[field], originalHost[field]) {
			t.Errorf("HostConfig.%s = %#v, want %#v", field, host[field], originalHost[field])
		}
	}
	binds := toStrings(host["Binds"])
	sort.Strings(binds)
	var anonymous []string
	for _, mount := range container.Mounts {
		if mount.Type == "volume" && mount.Name != "wyr-named" {
			anonymous = append(anonymous, mount.Name+":"+mount.Destination+":rw")
		}
	}
	want := append([]string{"wyr-named:/named", "/srv/fixture/bind:/bind:ro"}, anonymous...)
	sort.Strings(want)
	if !reflect.DeepEqual(binds, want) {
		t.Errorf("Binds = %v, want %v", binds, want)
	}
	mounts := host["Mounts"].([]any)
	if len(mounts) != 1 || mounts[0].(map[string]any)["Source"] != consumerDirectory || mounts[0].(map[string]any)["Target"] != "/run/wyrwood" {
		t.Errorf("Mounts = %#v", mounts)
	}
	if groups := toStrings(host["GroupAdd"]); !contains(groups, "1000") {
		t.Errorf("GroupAdd = %v", groups)
	}
	endpoints := body["NetworkingConfig"].(map[string]any)["EndpointsConfig"].(map[string]any)
	if len(endpoints) != 2 {
		t.Fatalf("EndpointsConfig = %#v", endpoints)
	}
	if aliases := toStrings(endpoints["wyr-a"].(map[string]any)["Aliases"]); !reflect.DeepEqual(aliases, []string{"web-alias"}) {
		t.Errorf("wyr-a aliases = %v", aliases)
	}
	if aliases := toStrings(endpoints["wyr-b"].(map[string]any)["Aliases"]); !reflect.DeepEqual(aliases, []string{"second-alias"}) {
		t.Errorf("wyr-b aliases = %v", aliases)
	}
}

func TestBuildCreateRequestPinsTheRunningImage(t *testing.T) {
	container, _ := loadFixture(t, "inspect-created.json")
	request, err := BuildCreateRequest(container, policy.DefaultContract(), consumerDirectory, "sha256:moved")
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	_ = json.Unmarshal(request.Body, &body)
	if body["Image"] != container.Image || request.Running {
		t.Fatalf("Image = %v running = %v", body["Image"], request.Running)
	}
}

// TestRecreateAgainstRealEngine recreates a container through the engine and
// verifies the result field by field. It skips without a reachable engine.
func TestRecreateAgainstRealEngine(t *testing.T) {
	client := engine.NewClient("/var/run/docker.sock")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if _, err := client.List(ctx); err != nil {
		t.Skip("Docker Engine not reachable")
	}
	image := os.Getenv("WYRWOOD_TEST_IMAGE")
	if image == "" {
		image = "openbao/openbao:2.4.1"
	}
	if _, err := client.ImageID(ctx, image); err != nil {
		t.Skipf("test image %s not present", image)
	}
	name := "wyrwood-recreate-test"
	cleanup := func() {
		if container, err := client.Inspect(context.Background(), name); err == nil {
			_ = client.Stop(context.Background(), container.ID, 0)
			_ = client.Remove(context.Background(), container.ID)
		}
	}
	cleanup()
	t.Cleanup(cleanup)
	directory := t.TempDir()
	create, _ := json.Marshal(map[string]any{
		"Image": image, "Entrypoint": []string{"/bin/sh"}, "Cmd": []string{"-c", "sleep 3600"},
		"Env": []string{"KEEP=1"}, "Labels": map[string]string{"devcontainer.local_folder": "/src/app"},
		"Volumes":    map[string]any{"/data": map[string]any{}},
		"HostConfig": map[string]any{"RestartPolicy": map[string]any{"Name": "on-failure", "MaximumRetryCount": 2}, "Memory": 67108864},
	})
	id, err := client.Create(ctx, name, create)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Start(ctx, id); err != nil {
		t.Fatal(err)
	}
	before, err := client.Inspect(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	imageID, _ := client.ImageID(ctx, before.Config.Image)
	request, err := BuildCreateRequest(before, groupContract(), directory, imageID)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Stop(ctx, id, time.Duration(request.Stop)*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := client.Remove(ctx, id); err != nil {
		t.Fatal(err)
	}
	newID, err := client.Create(ctx, request.Name, request.Body)
	if err != nil {
		t.Fatalf("Create() = %v", err)
	}
	if err := client.Start(ctx, newID); err != nil {
		t.Fatal(err)
	}
	after, err := client.Inspect(ctx, newID)
	if err != nil {
		t.Fatal(err)
	}
	if after.ShortName() != name || after.State.Status != "running" || after.Image != before.Image ||
		!reflect.DeepEqual(after.Config.Labels, before.Config.Labels) {
		t.Fatalf("recreated container differs: %#v", after)
	}
	if failed := Check(after, groupContract(), directory, func(uint32) bool { return true }); len(failed) != 0 {
		t.Fatalf("recreated container does not conform: %v", failed)
	}
	beforeVolumes, afterVolumes := volumeNames(before), volumeNames(after)
	if !reflect.DeepEqual(beforeVolumes, afterVolumes) {
		t.Fatalf("anonymous volumes changed: %v -> %v", beforeVolumes, afterVolumes)
	}
}

func volumeNames(container engine.Container) map[string]string {
	names := map[string]string{}
	for _, mount := range container.Mounts {
		if mount.Type == "volume" {
			names[mount.Destination] = mount.Name
		}
	}
	return names
}

func toStrings(value any) []string {
	items, _ := value.([]any)
	result := make([]string, 0, len(items))
	for _, item := range items {
		result = append(result, item.(string))
	}
	return result
}

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func TestOwnerOnlySocketAccess(t *testing.T) {
	for _, user := range []string{"", "root", "root:1234", "0", "0:1234", fmt.Sprint(os.Geteuid()), fmt.Sprintf("%d:1234", os.Geteuid()), "12345", "12345:0", "app", "app:0"} {
		t.Run(user, func(t *testing.T) {
			container, err := engine.ParseInspect([]byte(fmt.Sprintf(`{"Config":{"User":%q}}`, user)))
			if err != nil {
				t.Fatal(err)
			}
			want := !strings.HasPrefix(user, "12345") && !strings.HasPrefix(user, "app")
			if got := OwnerOnlyReachable(container.Config.User); got != want {
				t.Fatalf("OwnerOnlyReachable(%q) = %v, want %v", user, got, want)
			}
			if got := SocketReachable(container, nil); got != want {
				t.Fatalf("SocketReachable(%q, nil) = %v, want %v", user, got, want)
			}
		})
	}
}

func TestAccessGroupSocketAccess(t *testing.T) {
	group := uint32(1000)
	for _, test := range []struct {
		name, user string
		groups     []string
		want       bool
	}{
		{"outside group", "2000:2000", nil, false},
		{"primary group", "2000:1000", nil, true},
		{"supplementary group", "2000:2000", []string{"3000", "1000"}, true},
		{"supplementary group without primary", "2000", []string{"1000"}, true},
		{"wrong supplementary group", "2000:2000", []string{"3000"}, false},
		{"unknown primary group", "2000", nil, false},
		{"named primary group", "2000:staff", nil, false},
		{"named supplementary group", "2000:2000", []string{"staff"}, false},
		{"named user", "app:1000", nil, false},
		{"named user with supplementary group", "app", []string{"1000"}, false},
		{"default root", "", nil, true},
		{"numeric root", "0:2000", nil, true},
		{"named root", "root:2000", nil, true},
		{"agent uid", fmt.Sprintf("%d:2000", os.Geteuid()), nil, true},
		{"leading zero group", "2000:01000", nil, true},
		{"leading zero supplementary group", "2000:2000", []string{"01000"}, true},
		{"invalid uid", "4294967296:1000", nil, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw, err := json.Marshal(map[string]any{"Config": map[string]any{"User": test.user}, "HostConfig": map[string]any{"GroupAdd": test.groups}})
			if err != nil {
				t.Fatal(err)
			}
			container, err := engine.ParseInspect(raw)
			if err != nil {
				t.Fatal(err)
			}
			if got := SocketReachable(container, &group); got != test.want {
				t.Fatalf("SocketReachable(user=%q, groups=%v) = %v, want %v", test.user, test.groups, got, test.want)
			}
		})
	}
}
