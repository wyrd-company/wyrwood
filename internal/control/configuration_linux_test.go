//go:build linux

// ---
// relationships:
//   verifies: control-interface
// ---

package control

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestConfigurationRequestsAreClosedAndBounded(t *testing.T) {
	t.Parallel()

	zero := 0
	one := 1
	revision := strings.Repeat("a", 64)
	consumerID := strings.Repeat("b", 64)
	tests := []struct {
		name    string
		request Request
		want    ErrorCode
	}{
		{name: "first page", request: Request{Version: Version, Operation: OperationConfiguration, Offset: &zero, Limit: &one}, want: ErrorNone},
		{name: "later page", request: Request{Version: Version, Operation: OperationConfiguration, Offset: &one, Limit: &one, ExpectedRevision: &revision}, want: ErrorNone},
		{name: "later page without revision", request: Request{Version: Version, Operation: OperationConfiguration, Offset: &one, Limit: &one}, want: ErrorBadRequest},
		{name: "first page with revision", request: Request{Version: Version, Operation: OperationConfiguration, Offset: &zero, Limit: &one, ExpectedRevision: &revision}, want: ErrorBadRequest},
		{name: "oversized page", request: Request{Version: Version, Operation: OperationConfiguration, Offset: &zero, Limit: pointerTo(MaximumConfigurationPageSize + 1)}, want: ErrorBadRequest},
		{name: "set upstream", request: Request{Version: Version, Operation: OperationSetUpstream, ExpectedRevision: &revision, Upstream: stringPointer("/run/sample/agent.sock")}, want: ErrorNone},
		{name: "set upstream foreign field", request: Request{Version: Version, Operation: OperationSetUpstream, ExpectedRevision: &revision, Upstream: stringPointer("/run/sample/agent.sock"), Limit: &one}, want: ErrorBadRequest},
		{name: "put consumer", request: Request{Version: Version, Operation: OperationPutConsumer, ExpectedRevision: &revision, Consumer: &ConfigurationConsumerInput{Name: "sample", Socket: "/run/sample/agent.sock", Fingerprints: []string{}}}, want: ErrorNone},
		{name: "put replacement", request: Request{Version: Version, Operation: OperationPutConsumer, ExpectedRevision: &revision, ConsumerID: &consumerID, Consumer: &ConfigurationConsumerInput{Name: "sample", Socket: "/run/sample/agent.sock", Fingerprints: []string{}}}, want: ErrorNone},
		{name: "retire consumer", request: Request{Version: Version, Operation: OperationRetireConsumer, ExpectedRevision: &revision, ConsumerID: &consumerID}, want: ErrorNone},
		{name: "bad revision", request: Request{Version: Version, Operation: OperationRetireConsumer, ExpectedRevision: stringPointer("A"), ConsumerID: &consumerID}, want: ErrorBadRequest},
		{name: "bad consumer id", request: Request{Version: Version, Operation: OperationRetireConsumer, ExpectedRevision: &revision, ConsumerID: stringPointer("subject")}, want: ErrorBadRequest},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := validateRequest(test.request); got != test.want {
				t.Fatalf("validateRequest() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestMaximumConfigurationMutationAndPageFitControlFrames(t *testing.T) {
	t.Parallel()

	fingerprints := make([]string, 1024)
	for index := range fingerprints {
		digest := make([]byte, 32)
		digest[0] = byte(index >> 8)
		digest[1] = byte(index)
		fingerprints[index] = "SHA256:" + base64.RawStdEncoding.EncodeToString(digest)
	}
	input := ConfigurationConsumerInput{
		Name: strings.Repeat("界", MaximumConsumerNameCharacters), Socket: "/" + strings.Repeat("s", 106), Fingerprints: fingerprints,
	}
	revision := strings.Repeat("a", 64)
	request := Request{Version: Version, Operation: OperationPutConsumer, ExpectedRevision: &revision, Consumer: &input}
	if _, err := encodeJSONFrame(MaximumRequestBytes, request); err != nil {
		t.Fatalf("maximum consumer mutation does not fit request frame: %v", err)
	}
	consumers := make([]ConfigurationConsumer, MaximumConfigurationPageSize)
	for index := range consumers {
		consumers[index] = ConfigurationConsumer{ID: strings.Repeat("b", 64), ConfigurationConsumerInput: input}
	}
	response := Response{Version: Version, OK: true, Error: ErrorNone, Configuration: &ConfigurationResult{
		Revision: revision, Upstream: "/run/upstream/agent.sock", Timeouts: ConfigurationTimeouts{Connect: "5s", List: "5s", Replay: "5s", Sign: "2m"},
		TotalConsumers: len(consumers), Consumers: consumers, Complete: true,
	}}
	if _, err := encodeJSONFrame(MaximumResponseBytes, response); err != nil {
		t.Fatalf("maximum configuration page does not fit response frame: %v", err)
	}
}

func stringPointer(value string) *string { return &value }

func TestConfigurationClientRejectsInvalidProjection(t *testing.T) {
	t.Parallel()

	offset := 0
	limit := 1
	request := Request{Version: Version, Operation: OperationConfiguration, Offset: &offset, Limit: &limit}
	response := Response{Version: Version, OK: true, Error: ErrorNone, Configuration: &ConfigurationResult{
		Revision: strings.Repeat("a", 64), Upstream: "/run/sample/agent.sock",
		Timeouts:       ConfigurationTimeouts{Connect: "5s", List: "5s", Replay: "5s", Sign: "2m"},
		TotalConsumers: 1, Offset: 0, Consumers: []ConfigurationConsumer{}, Complete: true,
	}}
	if err := validateResponse(request, response); err == nil {
		t.Fatal("validateResponse() accepted a completed page missing its declared consumer")
	}
}
