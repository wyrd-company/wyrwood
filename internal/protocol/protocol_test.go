// ---
// relationships:
//   verifies: agent-controller-protocol
// ---

package protocol

import (
	"bytes"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/wyrd-company/wyrwood/internal/policy"
	"github.com/wyrd-company/wyrwood/internal/schematest"
)

var containerID = strings.Repeat("ab", 32)

func sampleMessages() []Message {
	return []Message{
		Hello{AgentVersion: "0.2.0", AllowRecreate: true},
		Inventory{Containers: []Container{}},
		Inventory{Containers: []Container{{
			ID: containerID, Name: "web", State: StateRunning, Image: "ghcr.io/example/web:1",
			Keys:     []Key{{Kind: KeyCompose, Value: "shop/web"}, {Kind: KeyName, Value: "web"}},
			Mounts:   []Mount{{Source: "/run/wyrwood/containers/web", Target: "/run/wyrwood"}},
			EnvNames: []string{"SSH_AUTH_SOCK", "VAULT_ADDR"},
		}}},
		ContractResult{Binding: "b-1", Outcome: OutcomeNonConforming, FailedItems: append([]FailedItem(nil), FailedItems...)},
		ContractResult{Binding: "b-1", Outcome: OutcomeRecreated, ContainerID: containerID},
		ContractResult{Binding: "b-1", Outcome: OutcomeRecreateFailed, Reason: ReasonCreateFailed},
		CredentialRequest{Binding: "b-1"},
		PolicySet{OpenBao: OpenBao{Address: "https://bao.example:8200", CAPEM: "-----BEGIN CERTIFICATE-----", Namespace: "team", TransitMount: "transit", SSHMount: "ssh"}, Bindings: []Binding{{
			Binding: "b-1", Key: Key{Kind: KeyName, Value: "web"}, Policy: (policy.New("teal", `path "kv/*" {}`)).Runtime(policy.DefaultSettings()), Assignment: ((policy.New("teal", `path "kv/*" {}`)).Runtime(policy.DefaultSettings())).Identity(),
		}}},
		PolicySet{OpenBao: OpenBao{Address: "http://127.0.0.1:8200"}, Bindings: []Binding{}},
		Credential{Binding: "b-1", AppRoleMount: "approle", RoleID: "role", WrappedSecretID: "wrapped", Assignment: "assignment"},
		RecreateRequest{Binding: "b-1"},
		Unbind{Binding: "b-1"},
		ResultRecorded{Binding: "b-1", Outcome: OutcomeConforming},
		ResultRecorded{Binding: "b-1", Outcome: OutcomeRecreateFailed, Reason: ReasonStartFailed},
		TokenAccessor{Binding: "b-1", Accessor: "oc22UEpiKGOntlXyrRKn7RBF", Assignment: "assignment"},
		TokenAccessor{Binding: "b-1", Accessor: "oc22UEpiKGOntlXyrRKn7RBF.ns1", Assignment: "assignment"},
		AccessorRecorded{Binding: "b-1", Accessor: "oc22UEpiKGOntlXyrRKn7RBF", Assignment: "assignment"},
	}
}

func TestEveryMessageRoundTripsAndValidatesAgainstSchema(t *testing.T) {
	schema := schematest.Compile(t, schematest.AgentControllerMessage)
	seen := map[Type]bool{}
	for _, message := range sampleMessages() {
		line, err := Encode(message)
		if err != nil {
			t.Fatalf("Encode(%T) = %v", message, err)
		}
		if err := schematest.Validate(schema, line); err != nil {
			t.Fatalf("%s does not validate: %v", line, err)
		}
		decoded, err := Decode(bytes.TrimSuffix(line, []byte("\n")))
		if err != nil {
			t.Fatalf("Decode(%s) = %v", line, err)
		}
		if !reflect.DeepEqual(decoded, message) {
			t.Fatalf("round trip = %#v, want %#v", decoded, message)
		}
		seen[message.MessageType()] = true
	}
	for _, messageType := range Types {
		if !seen[messageType] {
			t.Errorf("type %s is not covered", messageType)
		}
	}
	properties := schematest.Load(t, schematest.AgentControllerMessage)["properties"].(map[string]any)
	raw := properties["type"].(map[string]any)["enum"].([]any)
	if len(raw) != len(Types) {
		t.Fatalf("schema types = %v, Go types = %v", raw, Types)
	}
	for index, value := range raw {
		if value.(string) != string(Types[index]) {
			t.Fatalf("schema types = %v, Go types = %v", raw, Types)
		}
	}
}

func TestDecodeRejectsInvalidLines(t *testing.T) {
	for name, line := range map[string]string{
		"unknown-field":   `{"version":2,"type":"unbind","binding":"b-1","token":"x"}`,
		"version":         `{"version":1,"type":"unbind","binding":"b-1"}`,
		"version-float":   `{"version":2.0,"type":"unbind","binding":"b-1"}`,
		"missing-version": `{"type":"unbind","binding":"b-1"}`,
		"type":            `{"version":2,"type":"exec","binding":"b-1"}`,
		"missing-field":   `{"version":2,"type":"credential","binding":"b-1","approle-mount":"approle","role-id":"r"}`,
		"binding":         `{"version":2,"type":"unbind","binding":"B 1"}`,
		"container-id":    `{"version":2,"type":"inventory","containers":[{"id":"short","name":"x","state":"running","keys":[{"kind":"name","value":"x"}]}]}`,
		"no-keys":         `{"version":2,"type":"inventory","containers":[{"id":"` + containerID + `","name":"x","state":"running","keys":[]}]}`,
		"outcome":         `{"version":2,"type":"contract-result","binding":"b-1","outcome":"fine"}`,
		"not-json":        `{"version":2,`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode([]byte(line)); !errors.Is(err, ErrInvalid) {
				t.Fatalf("Decode() = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestConnRejectsOversizeLines(t *testing.T) {
	var stream bytes.Buffer
	stream.WriteString(strings.Repeat("x", MaximumLineBytes+1) + "\n")
	conn := NewConn(&readWriter{Reader: &stream, Writer: io.Discard})
	if _, err := conn.Receive(); !errors.Is(err, ErrLineTooLong) {
		t.Fatalf("Receive() = %v, want ErrLineTooLong", err)
	}
	if _, err := Encode(Hello{AgentVersion: strings.Repeat("v", MaximumLineBytes)}); !errors.Is(err, ErrLineTooLong) {
		t.Fatalf("Encode() = %v, want ErrLineTooLong", err)
	}
}

func TestConnExchangesMessages(t *testing.T) {
	var stream bytes.Buffer
	conn := NewConn(&readWriter{Reader: &stream, Writer: &stream})
	for _, message := range sampleMessages() {
		if err := conn.Send(message); err != nil {
			t.Fatal(err)
		}
	}
	for _, want := range sampleMessages() {
		got, err := conn.Receive()
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("Receive() = %#v, %v; want %#v", got, err, want)
		}
	}
	if _, err := conn.Receive(); !errors.Is(err, io.EOF) {
		t.Fatalf("Receive() at end = %v", err)
	}
}

func TestCredentialFormattingHidesWrappedSecret(t *testing.T) {
	credential := Credential{Binding: "b-1", AppRoleMount: "approle", RoleID: "role", WrappedSecretID: "s.wrapped-value", Assignment: "assignment"}
	for _, formatted := range []string{credential.String(), credential.GoString()} {
		if strings.Contains(formatted, "wrapped-value") {
			t.Fatalf("formatted credential leaks: %q", formatted)
		}
	}
}

type readWriter struct {
	io.Reader
	io.Writer
}

func TestHelloVersionIsOptional(t *testing.T) {
	schema := schematest.Compile(t, schematest.AgentControllerMessage)
	for _, line := range []string{
		`{"version":1,"type":"hello","allow-recreate":false}`,
		`{"version":1,"type":"hello","allow-recreate":false,"agent-version":""}`,
	} {
		if err := schematest.Validate(schema, []byte(line)); err != nil {
			t.Fatalf("legacy hello does not validate: %v", err)
		}
		message, err := Decode([]byte(line))
		if err != nil || message != (Hello{}) {
			t.Fatalf("legacy hello = %#v, %v", message, err)
		}
	}
}
