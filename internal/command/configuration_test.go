// ---
// relationships:
//   verifies: command-line-interface
// ---

package command

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/wyrd-company/wyrwood/internal/config"
	"github.com/wyrd-company/wyrwood/internal/control"
)

const (
	revisionA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	revisionB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	consumerA = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
)

func configurationPage(offset, total int, complete bool, consumers ...control.ConfigurationConsumer) control.ConfigurationResult {
	return control.ConfigurationResult{
		Revision: revisionA, Upstream: "/tmp/source.sock",
		Timeouts:       control.ConfigurationTimeouts{Connect: "5s", List: "6s", Replay: "7s", Sign: "8s"},
		TotalConsumers: total, Offset: offset, Consumers: consumers, Complete: complete,
	}
}

func TestConfigurationShowUsesCoherentPaginationAndClosedJSON(t *testing.T) {
	first := control.ConfigurationConsumer{ID: consumerA, ConfigurationConsumerInput: control.ConfigurationConsumerInput{
		Name: "line\nlabel", Socket: "/tmp/alpha.sock", Fingerprints: []string{sampleFingerprint},
	}}
	group := uint32(42)
	second := control.ConfigurationConsumer{ID: revisionB, ConfigurationConsumerInput: control.ConfigurationConsumerInput{
		Name: "second", Socket: "/tmp/beta.sock", AccessGroup: &group, Fingerprints: []string{},
	}}
	client := &fakeClient{configurationResults: []control.ConfigurationResult{
		configurationPage(0, 2, false, first),
		configurationPage(1, 2, true, second),
	}}

	exitCode, stdout, stderr := execute(t, []string{"configuration", "show", "--output=json"}, testDependencies(client))
	want := `{"version":1,"command":"configuration-show","ok":true,"result":{"revision":"` + revisionA + `","upstream":"/tmp/source.sock","timeouts":{"connect":"5s","list":"6s","replay":"7s","sign":"8s"},"consumers":[{"id":"` + consumerA + `","name":"line\nlabel","socket":"/tmp/alpha.sock","fingerprints":["` + sampleFingerprint + `"]},{"id":"` + revisionB + `","name":"second","socket":"/tmp/beta.sock","access_group":42,"fingerprints":[]}]}}` + "\n"
	if exitCode != exitSuccess || stdout != want || stderr != "" {
		t.Fatalf("configuration show = (%d, %q, %q), want %q", exitCode, stdout, stderr, want)
	}
	wantRequests := []configurationRequest{{offset: 0, limit: control.MaximumConfigurationPageSize}, {offset: 1, limit: control.MaximumConfigurationPageSize, expectedRevision: revisionA}}
	if !reflect.DeepEqual(client.configurationRequests, wantRequests) {
		t.Fatalf("configuration requests = %#v, want %#v", client.configurationRequests, wantRequests)
	}
}

func TestConfigurationShowHumanOutputQuotesEveryDisplayValue(t *testing.T) {
	client := &fakeClient{configurationResults: []control.ConfigurationResult{configurationPage(0, 1, true,
		control.ConfigurationConsumer{ID: consumerA, ConfigurationConsumerInput: control.ConfigurationConsumerInput{
			Name: "line\nlabel", Socket: "/tmp/alpha.sock", Fingerprints: []string{sampleFingerprint},
		}},
	)}}
	exitCode, stdout, stderr := execute(t, []string{"configuration", "show"}, testDependencies(client))
	want := "Revision: \"" + revisionA + "\"\nUpstream: \"/tmp/source.sock\"\nTimeouts: connect=\"5s\" list=\"6s\" replay=\"7s\" sign=\"8s\"\nConsumers: 1\nConsumer \"" + consumerA + "\": name=\"line\\nlabel\" socket=\"/tmp/alpha.sock\" access-group=- fingerprints=[\"" + sampleFingerprint + "\"]\n"
	if exitCode != exitSuccess || stdout != want || stderr != "" {
		t.Fatalf("configuration show = (%d, %q, %q), want %q", exitCode, stdout, stderr, want)
	}
}

func TestConfigurationShowEmptyCollectionIsExplicit(t *testing.T) {
	client := &fakeClient{configurationResults: []control.ConfigurationResult{configurationPage(0, 0, true)}}
	exitCode, stdout, stderr := execute(t, []string{"configuration", "show"}, testDependencies(client))
	if exitCode != exitSuccess || !strings.HasSuffix(stdout, "Consumers: 0\n") || stderr != "" {
		t.Fatalf("configuration show = (%d, %q, %q)", exitCode, stdout, stderr)
	}
}

func TestConfigurationMutationsUseExactDaemonOperations(t *testing.T) {
	group := uint32(42)
	tests := []struct {
		name     string
		args     []string
		client   *fakeClient
		wantCall string
		want     string
		assert   func(*testing.T, *fakeClient)
	}{
		{
			name: "set upstream", args: []string{"configuration", "set-upstream", "--revision", revisionA, "--socket", "/tmp/replacement.sock", "--output=json"},
			client:   &fakeClient{setUpstreamResult: control.ConfigurationChangeResult{Operation: control.OperationSetUpstream, Revision: revisionB, Changed: true}},
			wantCall: "set-upstream",
			want:     `{"version":1,"command":"configuration-set-upstream","ok":true,"result":{"revision":"` + revisionB + `","changed":true}}` + "\n",
			assert: func(t *testing.T, client *fakeClient) {
				if client.setUpstreamRevision != revisionA || client.setUpstreamSocket != "/tmp/replacement.sock" {
					t.Fatalf("set upstream arguments = %q, %q", client.setUpstreamRevision, client.setUpstreamSocket)
				}
			},
		},
		{
			name: "set timeouts", args: []string{"configuration", "set-timeouts", "--revision=" + revisionA, "--connect", "1s", "--list=2s", "--replay", "3s", "--sign=4s", "--output=json"},
			client:   &fakeClient{setTimeoutsResult: control.ConfigurationChangeResult{Operation: control.OperationSetTimeouts, Revision: revisionB, Changed: false}},
			wantCall: "set-timeouts",
			want:     `{"version":1,"command":"configuration-set-timeouts","ok":true,"result":{"revision":"` + revisionB + `","changed":false}}` + "\n",
			assert: func(t *testing.T, client *fakeClient) {
				want := control.ConfigurationTimeouts{Connect: "1s", List: "2s", Replay: "3s", Sign: "4s"}
				if client.setTimeoutsRevision != revisionA || client.setTimeoutsValue != want {
					t.Fatalf("set timeouts arguments = %q, %#v", client.setTimeoutsRevision, client.setTimeoutsValue)
				}
			},
		},
		{
			name: "put consumer", args: []string{"consumer", "put", "--revision", revisionA, "--id", consumerA, "--name", "sample", "--socket", "/tmp/sample.sock", "--access-group", "42", "--fingerprint", sampleFingerprint, "--fingerprint=" + strings.Replace(sampleFingerprint, "AAA", "BAA", 1), "--output=json"},
			client:   &fakeClient{putConsumerResult: control.ConfigurationChangeResult{Operation: control.OperationPutConsumer, Revision: revisionB, Changed: true, ConsumerID: stringPointer(revisionB)}},
			wantCall: "put-consumer",
			want:     `{"version":1,"command":"consumer-put","ok":true,"result":{"revision":"` + revisionB + `","changed":true,"consumer_id":"` + revisionB + `"}}` + "\n",
			assert: func(t *testing.T, client *fakeClient) {
				if client.putConsumerRevision != revisionA || client.putConsumerID == nil || *client.putConsumerID != consumerA || client.putConsumerValue.Name != "sample" || client.putConsumerValue.Socket != "/tmp/sample.sock" || client.putConsumerValue.AccessGroup == nil || *client.putConsumerValue.AccessGroup != group || len(client.putConsumerValue.Fingerprints) != 2 {
					t.Fatalf("put consumer arguments = %#v", client.putConsumerValue)
				}
			},
		},
		{
			name: "retire consumer", args: []string{"consumer", "retire", "--revision", revisionA, "--id", consumerA, "--output=json"},
			client:   &fakeClient{retireConsumerResult: control.ConfigurationChangeResult{Operation: control.OperationRetireConsumer, Revision: revisionB, Changed: true, ConsumerID: stringPointer(consumerA)}},
			wantCall: "retire-consumer",
			want:     `{"version":1,"command":"consumer-retire","ok":true,"result":{"revision":"` + revisionB + `","changed":true,"consumer_id":"` + consumerA + `"}}` + "\n",
			assert: func(t *testing.T, client *fakeClient) {
				if client.retireConsumerRevision != revisionA || client.retireConsumerID != consumerA {
					t.Fatalf("retire consumer arguments = %q, %q", client.retireConsumerRevision, client.retireConsumerID)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			exitCode, stdout, stderr := execute(t, test.args, testDependencies(test.client))
			if exitCode != exitSuccess || stderr != "" || stdout != test.want {
				t.Fatalf("run = (%d, %q, %q), want %q", exitCode, stdout, stderr, test.want)
			}
			if !reflect.DeepEqual(test.client.calls, []string{test.wantCall}) {
				t.Fatalf("calls = %v", test.client.calls)
			}
			test.assert(t, test.client)
		})
	}
}

func TestConsumerPutWithoutIDCreatesConsumerAndReplacesCompleteFingerprintSet(t *testing.T) {
	client := &fakeClient{putConsumerResult: control.ConfigurationChangeResult{Operation: control.OperationPutConsumer, Revision: revisionB, Changed: true, ConsumerID: stringPointer(consumerA)}}
	exitCode, _, stderr := execute(t, []string{"consumer", "put", "--revision", revisionA, "--name", "sample", "--socket", "/tmp/sample.sock"}, testDependencies(client))
	if exitCode != exitSuccess || stderr != "" || client.putConsumerID != nil || client.putConsumerValue.Fingerprints == nil || len(client.putConsumerValue.Fingerprints) != 0 {
		t.Fatalf("consumer create = (%d, stderr %q, id %#v, fingerprints %#v)", exitCode, stderr, client.putConsumerID, client.putConsumerValue.Fingerprints)
	}
}

func TestConfigurationMutationHumanOutputCarriesCompleteResult(t *testing.T) {
	client := &fakeClient{retireConsumerResult: control.ConfigurationChangeResult{Operation: control.OperationRetireConsumer, Revision: revisionB, Changed: false, ConsumerID: stringPointer(consumerA)}}
	exitCode, stdout, stderr := execute(t, []string{"consumer", "retire", "--revision", revisionA, "--id", consumerA}, testDependencies(client))
	want := "Configuration revision: \"" + revisionB + "\"\nChanged: false\nConsumer: \"" + consumerA + "\"\n"
	if exitCode != exitSuccess || stdout != want || stderr != "" {
		t.Fatalf("run = (%d, %q, %q), want %q", exitCode, stdout, stderr, want)
	}
}

func TestConfigurationCommandsRejectPartialOrAmbiguousOptionsBeforeConnecting(t *testing.T) {
	tests := [][]string{
		{"configuration"}, {"configuration", "unknown"}, {"configuration", "show", "--revision", revisionA},
		{"configuration", "set-upstream", "--revision", revisionA},
		{"configuration", "set-upstream", "--revision", "not-a-revision", "--socket", "/tmp/source.sock"},
		{"configuration", "set-upstream", "--revision", revisionA, "--revision", revisionA, "--socket", "/tmp/source.sock"},
		{"configuration", "set-timeouts", "--revision", revisionA, "--connect", "1s", "--list", "2s", "--replay", "3s"},
		{"consumer"}, {"consumer", "put", "--revision", revisionA, "--name", "sample"},
		{"consumer", "put", "--revision", revisionA, "--name", "sample", "--socket", "/tmp/sample.sock", "--access-group", "4294967295"},
		{"consumer", "put", "--revision", revisionA, "--name", "sample", "--name", "second", "--socket", "/tmp/sample.sock"},
		{"consumer", "put", "--revision", revisionA, "--name", "sample", "--socket", "/tmp/sample.sock", "--fingerprint", sampleFingerprint, "--fingerprint", sampleFingerprint},
		{"consumer", "retire", "--revision", revisionA},
	}
	for _, args := range tests {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			client := successfulClient()
			exitCode, stdout, stderr := execute(t, append(args, "--output=json"), testDependencies(client))
			structured := len(args) > 1 && (args[1] == "show" || args[1] == "set-upstream" || args[1] == "set-timeouts" || args[1] == "put" || args[1] == "retire")
			if exitCode != exitUsage || stdout != "" || structured && !strings.Contains(stderr, `"code":"usage"`) || !structured && !strings.Contains(stderr, "command options are invalid") || len(client.calls) != 0 {
				t.Fatalf("%v = (%d, %q, %q), calls %v", args, exitCode, stdout, stderr, client.calls)
			}
		})
	}
}

func TestConsumerPutRejectsAnUnboundedFingerprintOptionSetBeforeConnecting(t *testing.T) {
	args := []string{"consumer", "put", "--revision", revisionA, "--name", "sample", "--socket", "/tmp/sample.sock"}
	for index := 0; index <= config.MaximumFingerprintsPerConsumer; index++ {
		digest := sha256.Sum256([]byte(strconv.Itoa(index)))
		args = append(args, "--fingerprint", "SHA256:"+base64.RawStdEncoding.EncodeToString(digest[:]))
	}
	client := successfulClient()
	exitCode, stdout, stderr := execute(t, append(args, "--output=json"), testDependencies(client))
	if exitCode != exitUsage || stdout != "" || !strings.Contains(stderr, `"code":"usage"`) || len(client.calls) != 0 {
		t.Fatalf("run = (%d, %q, %q), calls %v", exitCode, stdout, stderr, client.calls)
	}
}

func TestConfigurationFailuresAreCategoricalRedactedAndNotRetried(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantExit int
		wantCode string
	}{
		{name: "invalid candidate", err: &control.RemoteError{Code: control.ErrorConfigurationInvalid}, wantExit: exitApplyInvalid, wantCode: "configuration-invalid"},
		{name: "stale revision", err: &control.RemoteError{Code: control.ErrorConfigurationConflict}, wantExit: exitConfigurationConflict, wantCode: "configuration-conflict"},
		{name: "failed", err: &control.RemoteError{Code: control.ErrorConfigurationFailed}, wantExit: exitRequestFailed, wantCode: "configuration-failed"},
		{name: "uncertain durability", err: &control.RemoteError{Code: control.ErrorConfigurationDurabilityUncertain}, wantExit: exitConfigurationDurability, wantCode: "configuration-durability-uncertain"},
		{name: "upstream unavailable", err: &control.RemoteError{Code: control.ErrorUpstreamUnavailable}, wantExit: exitUpstream, wantCode: "upstream-unavailable"},
		{name: "transport", err: errors.New("private marker /tmp/private.sock"), wantExit: exitDaemonUnavailable, wantCode: "daemon-unavailable"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := &fakeClient{setUpstreamErr: test.err}
			exitCode, stdout, stderr := execute(t, []string{"configuration", "set-upstream", "--revision", revisionA, "--socket", "/tmp/source.sock", "--output=json"}, testDependencies(client))
			if exitCode != test.wantExit || stdout != "" || !strings.Contains(stderr, `"code":"`+test.wantCode+`"`) || strings.Contains(stderr, "private marker") || !strings.HasSuffix(stderr, "\n") {
				t.Fatalf("run = (%d, %q, %q)", exitCode, stdout, stderr)
			}
			if !reflect.DeepEqual(client.calls, []string{"set-upstream"}) {
				t.Fatalf("mutation retried: %v", client.calls)
			}
		})
	}
}

func TestMissingConsumerUsesReservedExitStatusTen(t *testing.T) {
	client := &fakeClient{retireConsumerErr: &control.RemoteError{Code: control.ErrorConfigurationNotFound}}
	exitCode, stdout, stderr := execute(t, []string{"consumer", "retire", "--revision", revisionA, "--id", consumerA, "--output=json"}, testDependencies(client))
	if exitCode != exitConfigurationNotFound || stdout != "" || !strings.Contains(stderr, `"code":"configuration-not-found"`) || !reflect.DeepEqual(client.calls, []string{"retire-consumer"}) {
		t.Fatalf("run = (%d, %q, %q), calls %v", exitCode, stdout, stderr, client.calls)
	}
}

func TestDuplicateConsumerCandidateIsCategoricallyInvalid(t *testing.T) {
	client := &fakeClient{putConsumerErr: &control.RemoteError{Code: control.ErrorConfigurationInvalid}}
	exitCode, stdout, stderr := execute(t, []string{"consumer", "put", "--revision", revisionA, "--name", "sample", "--socket", "/tmp/sample.sock", "--output=json"}, testDependencies(client))
	if exitCode != exitApplyInvalid || stdout != "" || !strings.Contains(stderr, `"code":"configuration-invalid"`) || !reflect.DeepEqual(client.calls, []string{"put-consumer"}) {
		t.Fatalf("run = (%d, %q, %q), calls %v", exitCode, stdout, stderr, client.calls)
	}
}

func TestConfigurationPaginationConflictProducesNoPartialOutputAndNoAutomaticRetry(t *testing.T) {
	client := &fakeClient{
		configurationResults: []control.ConfigurationResult{configurationPage(0, 17, false, control.ConfigurationConsumer{ID: consumerA, ConfigurationConsumerInput: control.ConfigurationConsumerInput{Name: "sample", Socket: "/tmp/sample.sock", Fingerprints: []string{}}})},
		configurationErrors:  []error{nil, &control.RemoteError{Code: control.ErrorConfigurationConflict}},
	}
	exitCode, stdout, stderr := execute(t, []string{"configuration", "show", "--output=json"}, testDependencies(client))
	if exitCode != exitConfigurationConflict || stdout != "" || !strings.Contains(stderr, `"code":"configuration-conflict"`) || len(client.configurationRequests) != 2 {
		t.Fatalf("run = (%d, %q, %q), requests %v", exitCode, stdout, stderr, client.configurationRequests)
	}
}

func TestConfigurationShowRejectsIncoherentPaginationWithoutPartialOutput(t *testing.T) {
	first := configurationPage(0, 2, false, control.ConfigurationConsumer{ID: consumerA, ConfigurationConsumerInput: control.ConfigurationConsumerInput{Name: "sample", Socket: "/tmp/alpha.sock", Fingerprints: []string{}}})
	tests := []struct {
		name string
		next control.ConfigurationResult
	}{
		{name: "total changed", next: configurationPage(1, 3, false, control.ConfigurationConsumer{ID: revisionB, ConfigurationConsumerInput: control.ConfigurationConsumerInput{Name: "second", Socket: "/tmp/beta.sock", Fingerprints: []string{}}})},
		{name: "metadata changed", next: func() control.ConfigurationResult {
			value := configurationPage(1, 2, true, control.ConfigurationConsumer{ID: revisionB, ConfigurationConsumerInput: control.ConfigurationConsumerInput{Name: "second", Socket: "/tmp/beta.sock", Fingerprints: []string{}}})
			value.Upstream = "/tmp/other.sock"
			return value
		}()},
		{name: "empty incomplete page", next: configurationPage(1, 2, false)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := &fakeClient{configurationResults: []control.ConfigurationResult{first, test.next}}
			exitCode, stdout, stderr := execute(t, []string{"configuration", "show", "--output=json"}, testDependencies(client))
			if exitCode != exitDaemonUnavailable || stdout != "" || !strings.Contains(stderr, `"code":"daemon-unavailable"`) || len(client.configurationRequests) != 2 {
				t.Fatalf("run = (%d, %q, %q), requests %v", exitCode, stdout, stderr, client.configurationRequests)
			}
		})
	}
}

func TestConfigurationHelpDocumentsExactGrammarWithoutRunningClient(t *testing.T) {
	client := successfulClient()
	tests := []struct {
		args []string
		want string
	}{
		{args: []string{"configuration", "--help"}, want: "configuration show"},
		{args: []string{"configuration", "set-upstream", "--help"}, want: "--revision REVISION --socket SOCKET"},
		{args: []string{"configuration", "set-timeouts", "--help"}, want: "--connect DURATION --list DURATION --replay DURATION --sign DURATION"},
		{args: []string{"consumer", "put", "--help"}, want: "[--fingerprint FINGERPRINT]..."},
		{args: []string{"consumer", "retire", "--help"}, want: "--revision REVISION --id ID"},
	}
	for _, test := range tests {
		exitCode, stdout, stderr := execute(t, test.args, testDependencies(client))
		if exitCode != exitSuccess || !strings.Contains(stdout, test.want) || stderr != "" || len(client.calls) != 0 {
			t.Fatalf("help %v = (%d, %q, %q), calls %v", test.args, exitCode, stdout, stderr, client.calls)
		}
	}
}

func stringPointer(value string) *string { return &value }
