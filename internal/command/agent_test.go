// ---
// relationships:
//   verifies: command-line-interface
// ---

package command

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/wyrd-company/wyrwood/internal/agent"
	"github.com/wyrd-company/wyrwood/internal/events"
	"github.com/wyrd-company/wyrwood/internal/linuxservice"
)

func TestAgentLoginProjectionsAndExitStatuses(t *testing.T) {
	deps := defaultDependencies()
	result := agent.LoginResult{AgentFingerprint: "SHA256:agent", ControllerFingerprint: "SHA256:controller"}
	var err error
	deps.agentLogin = func(_ context.Context, options agent.LoginOptions) (agent.LoginResult, error) {
		if options.ControllerURL != "ssh://controller:2222" {
			t.Fatalf("url = %q", options.ControllerURL)
		}
		if options.Announce != nil {
			options.Announce(result.AgentFingerprint)
		}
		return result, err
	}
	status, stdout, _ := runForTest(t, deps, "agent", "login", "ssh://controller:2222")
	if status != exitNotApproved || stdout != "Agent key: SHA256:agent\nController host key: SHA256:controller\nStatus: pending\nApprove this agent's key in the controller web interface, then start the agent.\n" {
		t.Fatalf("pending login = %d %q", status, stdout)
	}
	result.Approved = true
	status, stdout, _ = runForTest(t, deps, "agent", "login", "ssh://controller:2222", "--output", "json")
	if status != exitSuccess || stdout != `{"version":1,"agent-fingerprint":"SHA256:agent","controller-fingerprint":"SHA256:controller","status":"approved"}`+"\n" {
		t.Fatalf("approved login = %d %q", status, stdout)
	}
	for expected, failure := range map[int]error{
		exitLoginState: agent.ErrLoginState, exitUnreachable: agent.ErrUnreachable,
		exitHostKeyChange: agent.ErrHostKeyMismatch, exitUsage: agent.ErrInvalidURL,
	} {
		err = failure
		if status, _, _ := runForTest(t, deps, "agent", "login", "ssh://controller:2222"); status != expected {
			t.Errorf("login with %v = %d, want %d", failure, status, expected)
		}
	}
	if status, _, _ := runForTest(t, deps, "agent", "login"); status != exitUsage {
		t.Fatalf("login without URL = %d", status)
	}
}

func TestAgentQueriesUseOnlyTheControlSocket(t *testing.T) {
	deps := defaultDependencies()
	var operations []string
	deps.queryAgent = func(_ context.Context, request agent.ControlRequest, destination any) error {
		operations = append(operations, request.Operation)
		switch typed := destination.(type) {
		case *agent.Status:
			*typed = agent.Status{Version: 1, Agent: "host-a", Controller: "ssh://controller", Session: "connected", Containers: 2, Bindings: 1, Tokens: 1, Health: map[string]int{"healthy": 1}}
		case *agent.Containers:
			*typed = agent.Containers{Version: 1, Containers: []agent.ContainerStatus{{Name: "web", State: "running", BindingKey: "name:web", Policy: "teal", Conformance: "conforming", Token: "valid"}}}
		case *agent.Events:
			if request.Limit != 5 {
				t.Fatalf("limit = %d", request.Limit)
			}
			*typed = agent.Events{Version: 1, Events: []events.Record{{Time: "2026-01-01T00:00:00Z", Operation: events.OperationVaultRequest, Outcome: events.OutcomeOK, Mount: events.MountKV, Method: events.MethodGet, ContainerKey: "name:web"}}}
		}
		return nil
	}
	status, stdout, _ := runForTest(t, deps, "agent", "status")
	if status != exitSuccess || !strings.Contains(stdout, "Controller:  ssh://controller (connected)") || !strings.Contains(stdout, "Health:      healthy 1") {
		t.Fatalf("status = %d %q", status, stdout)
	}
	status, stdout, _ = runForTest(t, deps, "agent", "containers", "--output", "json")
	var containers agent.Containers
	if status != exitSuccess || json.Unmarshal([]byte(stdout), &containers) != nil || containers.Containers[0].Policy != "teal" {
		t.Fatalf("containers json = %d %q", status, stdout)
	}
	status, stdout, _ = runForTest(t, deps, "agent", "events", "--limit", "5")
	if status != exitSuccess || !strings.Contains(stdout, "vault-request") || !strings.Contains(stdout, "name:web GET kv") {
		t.Fatalf("events = %d %q", status, stdout)
	}
	if status, _, _ := runForTest(t, deps, "agent", "events", "--limit", "1001"); status != exitUsage {
		t.Fatalf("events limit bound = %d", status)
	}
	if status, _, _ := runForTest(t, deps, "agent", "status", "--config", "/tmp/x"); status != exitUsage {
		t.Fatalf("status accepted a path override: %d", status)
	}
	deps.queryAgent = func(context.Context, agent.ControlRequest, any) error { return agent.ErrControlUnavailable }
	if status, _, stderr := runForTest(t, deps, "agent", "status"); status != exitDaemon || !strings.Contains(stderr, "control socket unavailable") {
		t.Fatalf("daemon unavailable = %d %q", status, stderr)
	}
	if strings.Join(operations, ",") != "status,containers,events" {
		t.Fatalf("operations = %v", operations)
	}
}

func TestServiceProjectionsAndFailures(t *testing.T) {
	deps := defaultDependencies()
	deps.manageService = func(action string) (string, error) {
		if action == "install" {
			return "", linuxservice.ErrRequiresRoot
		}
		return "active", nil
	}
	status, stdout, _ := runForTest(t, deps, "agent", "service", "status")
	if status != exitSuccess || stdout != "wyrwood-agent.service: active\n" {
		t.Fatalf("service status = %d %q", status, stdout)
	}
	status, stdout, _ = runForTest(t, deps, "agent", "service", "start", "--output", "json")
	if status != exitSuccess || stdout != `{"version":1,"action":"start","state":"active"}`+"\n" {
		t.Fatalf("service start json = %d %q", status, stdout)
	}
	status, _, stderr := runForTest(t, deps, "agent", "service", "install")
	if status != exitOperational || !strings.Contains(stderr, "requires root") {
		t.Fatalf("service install = %d %q", status, stderr)
	}
	if status, _, _ := runForTest(t, deps, "agent", "service", "restart"); status != exitUsage {
		t.Fatalf("unknown action = %d", status)
	}
}
