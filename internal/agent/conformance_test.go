// ---
// relationships:
//   verifies: container-contract
// ---

package agent

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/wyrd-company/wyrwood/internal/config"
	"github.com/wyrd-company/wyrwood/internal/consumer"
	"github.com/wyrd-company/wyrwood/internal/engine"
	"github.com/wyrd-company/wyrwood/internal/engine/enginetest"
	"github.com/wyrd-company/wyrwood/internal/policy"
	"github.com/wyrd-company/wyrwood/internal/protocol"
)

func TestConformanceRequiresConsumerSockets(t *testing.T) {
	for _, scenario := range []string{"ready", "directory unavailable", "vault unavailable", "ssh unavailable", "no endpoints", "one listener", "wrong binding", "wrong group", "owner-only denied", "group sockets", "group denied", "group supplementary", "group named user", "group root"} {
		t.Run(scenario, func(t *testing.T) {
			paths := newPaths(t)
			if err := os.MkdirAll(paths.State, 0o700); err != nil {
				t.Fatal(err)
			}
			options := Options{Paths: paths, Config: config.Agent{ConsumerRoot: filepath.Join(paths.Runtime, "containers")}, Endpoints: probeEndpoints{}}
			if scenario == "no endpoints" {
				options.Endpoints = nil
			}
			instance, err := New(options)
			if err != nil {
				t.Fatal(err)
			}
			defer instance.shutdown()
			document := policy.New("teal", policy.StarterHCL+"").Runtime(policy.DefaultSettings())
			if scenario == "owner-only denied" {
				document.Contract.Enforcement = policy.EnforcementRecreate
				instance.config.AllowRecreate = true
				instance.engine = enginetest.New()
			}
			if strings.HasPrefix(scenario, "group ") {
				group := uint32(os.Getegid())
				document.Contract.AccessGroup = &group
			}
			bound := protocol.Binding{Binding: "b-1", Key: protocol.Key{Kind: protocol.KeyName, Value: "app"}, Policy: document, Assignment: (document).Identity()}
			app := engine.Container{ID: "container-1", Name: "/app"}
			if scenario == "owner-only denied" || strings.HasPrefix(scenario, "group ") {
				app.Config.User = "12345"
			}
			switch scenario {
			case "group sockets":
				app.Config.User += ":" + strconv.Itoa(os.Getegid())
			case "group denied":
				app.Config.User += ":" + strconv.Itoa(os.Getegid()+1)
			case "group supplementary":
				app.HostConfig.GroupAdd = []string{strconv.Itoa(os.Getegid())}
			case "group named user":
				app.Config.User = "app:" + strconv.Itoa(os.Getegid())
			case "group root":
				app.Config.User = "0:12345"
			}
			app.Mounts = []engine.Mount{{Type: "bind", Source: instance.root.DirectoryPath("app"), Destination: document.Contract.MountTarget}}
			for _, entry := range document.Contract.ExpandedEnv() {
				app.Config.Env = append(app.Config.Env, entry.Name+"="+entry.Value)
			}
			instance.containers[app.ID] = app
			instance.set.Bindings = []protocol.Binding{bound}
			path := instance.root.DirectoryPath("app")
			if scenario == "directory unavailable" {
				if err := os.WriteFile(path, nil, 0o600); err != nil {
					t.Fatal(err)
				}
			} else if scenario == "vault unavailable" || scenario == "ssh unavailable" {
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
				name := consumer.VaultSocket
				if scenario == "ssh unavailable" {
					name = consumer.SSHAgentSocket
				}
				if err := os.WriteFile(filepath.Join(path, name), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "owner-only denied" {
				instance.applyPolicySet(context.Background(), instance.set)
			} else {
				instance.applyLocked(context.Background())
			}
			if scenario == "one listener" {
				state := instance.consumers["app"]
				_ = state.listeners[1].Close()
				state.listeners = state.listeners[:1]
				instance.checkLocked(context.Background(), bound, []engine.Container{app})
			}
			if scenario == "wrong binding" {
				instance.consumers["app"].binding = "b-2"
				instance.checkLocked(context.Background(), bound, []engine.Container{app})
			}
			if scenario == "wrong group" {
				group := uint32(os.Getegid())
				instance.consumers["app"].group = &group
				instance.checkLocked(context.Background(), bound, []engine.Container{app})
			}
			result := instance.results[bound.Binding]
			wantOutcome := protocol.OutcomeNonConforming
			wantItems := []protocol.FailedItem{protocol.FailedConsumerDirectory}
			if scenario == "owner-only denied" || scenario == "group denied" || scenario == "group named user" {
				wantItems = []protocol.FailedItem{protocol.FailedSocketAccess}
			}
			if scenario == "ready" || scenario == "group sockets" || scenario == "group supplementary" || scenario == "group root" {
				wantOutcome, wantItems = protocol.OutcomeConforming, nil
			}
			if result.Outcome != wantOutcome || !reflect.DeepEqual(result.FailedItems, wantItems) {
				t.Fatalf("result = %+v, want %s %v", result, wantOutcome, wantItems)
			}
			listing := instance.ContainerStatuses().Containers[0]
			if listing.Conformance != string(wantOutcome) || !reflect.DeepEqual(listing.FailedItems, wantItems) {
				t.Fatalf("listing = %+v", listing)
			}
			if scenario == "ready" {
				for _, name := range []string{consumer.VaultSocket, consumer.SSHAgentSocket} {
					if got := probe(t, filepath.Join(path, name)); got == "unreachable" {
						t.Fatalf("%s is unreachable", name)
					}
				}
			}
		})
	}
}
