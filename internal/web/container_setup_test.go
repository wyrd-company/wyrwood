// ---
// relationships:
//   verifies: web-interface
// ---

package web

import (
	"encoding/csv"
	"encoding/json"
	"os/exec"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/wyrd-company/wyrwood/internal/policy"
	"github.com/wyrd-company/wyrwood/internal/protocol"
)

func TestBindingSetupUsesEffectiveContract(t *testing.T) {
	for _, test := range []struct{ source, target, value string }{
		{"/run/wyrwood/containers/sample", "/run/wyrwood", "plain"},
		{"/srv/sample $ROOT,\"quoted\"/'app", "/opt/sample sockets", "quote'\" dollar${EXAMPLE}\nnext\\line"},
	} {
		t.Run(test.source, func(t *testing.T) {
			container := protocol.Container{Name: "sample", Image: "alpine:latest", ConsumerDirectory: test.source}
			contract := policy.Contract{MountTarget: test.target, Env: map[string]string{
				"VAULT_ADDR": "unix://{mount-target}/vault.sock", "SAMPLE": test.value,
			}}
			setup := bindingSetup(container, contract)
			if setup == nil || setup.Source != test.source || setup.Target != test.target {
				t.Fatalf("setup = %#v", setup)
			}
			var document struct {
				Services map[string]struct {
					Image       string            `yaml:"image"`
					Name        string            `yaml:"container_name"`
					Environment map[string]string `yaml:"environment"`
					Volumes     []struct {
						Type, Source, Target string
						Bind                 struct {
							CreateHostPath bool `yaml:"create_host_path"`
						}
					}
				}
			}
			if err := yaml.Unmarshal([]byte(setup.Compose), &document); err != nil {
				t.Fatal(err)
			}
			service := document.Services["app"]
			literal := func(s string) string { return strings.ReplaceAll(s, "$$", "$") }
			if service.Image != container.Image || service.Name != container.Name || len(service.Volumes) != 1 {
				t.Fatalf("service = %#v", service)
			}
			mount := service.Volumes[0]
			if mount.Type != "bind" || literal(mount.Source) != test.source || mount.Target != test.target || mount.Bind.CreateHostPath {
				t.Fatalf("mount = %#v", mount)
			}
			if literal(service.Environment["SAMPLE"]) != test.value || service.Environment["VAULT_ADDR"] != "unix://"+test.target+"/vault.sock" {
				t.Fatalf("environment = %#v", service.Environment)
			}
			if strings.Contains(strings.ReplaceAll(setup.Compose, "$$", ""), "$") {
				t.Fatal("unescaped Compose interpolation")
			}

			// Execute only a test shell function, so shell quoting is tested by
			// the actual parser without creating a container or invoking Docker.
			script := "docker() { printf '%s\\0' \"$@\"; }\n" + setup.DockerRun
			output, err := exec.Command("sh", "-c", script).Output()
			if err != nil {
				t.Fatal(err)
			}
			args := strings.Split(strings.TrimSuffix(string(output), "\x00"), "\x00")
			want := []string{"run", "--name", "sample", "--mount", "", "--env", "SAMPLE=" + test.value, "--env", "VAULT_ADDR=unix://" + test.target + "/vault.sock", "alpine:latest"}
			if len(args) != len(want) {
				t.Fatalf("args = %#v", args)
			}
			record, err := csv.NewReader(strings.NewReader(args[4])).Read()
			if err != nil || !reflect.DeepEqual(record, []string{"type=bind", "source=" + test.source, "target=" + test.target}) {
				t.Fatalf("mount = %#v, %v", record, err)
			}
			args[4] = ""
			if !reflect.DeepEqual(args, want) {
				t.Fatalf("args = %#v", args)
			}
		})
	}
}

func TestBindingSetupRequiresAgentObservation(t *testing.T) {
	contract := policy.DefaultContract()
	for _, container := range []protocol.Container{
		{Name: "sample", Image: "alpine", Mounts: []protocol.Mount{{Source: "/wrong", Target: contract.MountTarget}}},
		{Name: "sample", ConsumerDirectory: "/srv/sample"},
	} {
		if setup := bindingSetup(container, contract); setup != nil {
			t.Fatalf("invented setup = %#v", setup)
		}
	}
}

func TestInventoryConsumerDirectoryRoundTrip(t *testing.T) {
	container := protocol.Container{ID: strings.Repeat("a", 64), Name: "sample", State: protocol.StateRunning,
		Keys: []protocol.Key{{Kind: protocol.KeyName, Value: "sample"}}, ConsumerDirectory: "/srv/sample"}
	line, err := protocol.Encode(protocol.Inventory{Containers: []protocol.Container{container}})
	if err != nil {
		t.Fatal(err)
	}
	message, err := protocol.Decode(line)
	if err != nil {
		t.Fatal(err)
	}
	if message.(protocol.Inventory).Containers[0].ConsumerDirectory != container.ConsumerDirectory {
		t.Fatal("lost consumer directory")
	}
	var raw map[string]any
	if err := json.Unmarshal(line, &raw); err != nil {
		t.Fatal(err)
	}
	delete(raw["containers"].([]any)[0].(map[string]any), "consumer-directory")
	old, _ := json.Marshal(raw)
	if _, err := protocol.Decode(old); err != nil {
		t.Fatalf("older inventory rejected: %v", err)
	}
}

func TestBindingSetupIncludesConfiguredAccessGroup(t *testing.T) {
	group := uint32(2300)
	contract := policy.DefaultContract()
	contract.AccessGroup = &group
	setup := bindingSetup(protocol.Container{Name: "sample", Image: "alpine", ConsumerDirectory: "/srv/sample"}, contract)
	var document map[string]any
	if err := yaml.Unmarshal([]byte(setup.Compose), &document); err != nil {
		t.Fatal(err)
	}
	service := document["services"].(map[string]any)["app"].(map[string]any)
	if !reflect.DeepEqual(service["group_add"], []any{"2300"}) || !strings.Contains(setup.DockerRun, "--group-add '2300'") {
		t.Fatalf("setup = %#v", setup)
	}
}
