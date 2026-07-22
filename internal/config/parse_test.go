// ---
// relationships: {}
// ---

package config

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseValidConfiguration(t *testing.T) {
	t.Parallel()

	firstFingerprint := testFingerprint(1)
	secondFingerprint := testFingerprint(2)
	input := fmt.Sprintf(`upstream: /run/upstream/agent.sock
consumers:
  - name: first consumer
    socket: /run/consumers/first/agent.sock
    access-group: 1200
    fingerprints:
      - %s
      - %s
  - name: second consumer
    socket: /run/consumers/second/agent.sock
    fingerprints: []
timeouts:
  connect: 5s
  list: 4s
  replay: 3s
  sign: 2m
`, firstFingerprint, secondFingerprint)

	configuration, err := Parse([]byte(input))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if configuration.Upstream != "/run/upstream/agent.sock" {
		t.Fatalf("Parse().Upstream = %q", configuration.Upstream)
	}
	if len(configuration.Consumers) != 2 {
		t.Fatalf("len(Parse().Consumers) = %d, want 2", len(configuration.Consumers))
	}
	first := configuration.Consumers[0]
	if first.AccessGroup == nil || *first.AccessGroup != 1200 {
		t.Fatalf("Parse().Consumers[0].AccessGroup = %v, want 1200", first.AccessGroup)
	}
	if len(first.Fingerprints) != 2 || first.Fingerprints[1] != secondFingerprint {
		t.Fatalf("Parse().Consumers[0].Fingerprints = %v", first.Fingerprints)
	}
	if configuration.Consumers[1].AccessGroup != nil {
		t.Fatalf("Parse().Consumers[1].AccessGroup = %v, want nil", configuration.Consumers[1].AccessGroup)
	}
	if configuration.Timeouts.Sign != 2*time.Minute {
		t.Fatalf("Parse().Timeouts.Sign = %s, want 2m", configuration.Timeouts.Sign)
	}
}

func TestParseRejectsInvalidConfiguration(t *testing.T) {
	t.Parallel()

	fingerprint := testFingerprint(1)
	valid := fmt.Sprintf(`upstream: /run/upstream/agent.sock
consumers:
  - name: first consumer
    socket: /run/consumers/first/agent.sock
    access-group: 1200
    fingerprints:
      - %s
  - name: second consumer
    socket: /run/consumers/second/agent.sock
    fingerprints: []
timeouts:
  connect: 5s
  list: 5s
  replay: 5s
  sign: 2m
`, fingerprint)

	tests := []struct {
		name        string
		input       string
		old         string
		replacement string
		want        string
	}{
		{name: "empty document", input: "", want: "document is empty"},
		{name: "multiple documents", input: valid + "---\n{}\n", want: "exactly one YAML document"},
		{name: "unknown root field", old: "upstream:", replacement: "unexpected: true\nupstream:", want: "unexpected (line 1, column 1): unknown field"},
		{name: "unknown consumer field", old: "    socket: /run/consumers/first/agent.sock", replacement: "    socket: /run/consumers/first/agent.sock\n    unexpected: true", want: "consumers[0].unexpected"},
		{name: "duplicate field", old: "upstream: /run/upstream/agent.sock", replacement: "upstream: /run/upstream/agent.sock\nupstream: /run/other/agent.sock", want: "upstream (line 2, column 1): field is defined more than once"},
		{name: "missing upstream", old: "upstream: /run/upstream/agent.sock\n", replacement: "", want: "upstream"},
		{name: "non-string name", old: "name: first consumer", replacement: "name: 42", want: "consumers[0].name"},
		{name: "relative upstream", old: "/run/upstream/agent.sock", replacement: "relative/agent.sock", want: "upstream"},
		{name: "root upstream", old: "/run/upstream/agent.sock", replacement: "/", want: "must name a socket below the filesystem root"},
		{name: "unclean upstream", old: "/run/upstream/agent.sock", replacement: "/run/upstream/../agent.sock", want: "canonical lexical form"},
		{name: "empty consumer name", old: "name: first consumer", replacement: `name: ""`, want: "consumers[0].name"},
		{name: "trimmed consumer name", old: "name: first consumer", replacement: `name: " first consumer"`, want: "leading or trailing whitespace"},
		{name: "duplicate consumer name", old: "name: second consumer", replacement: "name: first consumer", want: "duplicates consumers[0].name"},
		{name: "duplicate upstream socket", old: "/run/consumers/first/agent.sock", replacement: "/run/upstream/agent.sock", want: "duplicates upstream"},
		{name: "duplicate consumer socket", old: "/run/consumers/second/agent.sock", replacement: "/run/consumers/first/agent.sock", want: "duplicates consumers[0].socket"},
		{name: "root consumer socket", old: "/run/consumers/first/agent.sock", replacement: "/", want: "must name a socket below the filesystem root"},
		{name: "root parent", old: "/run/consumers/first/agent.sock", replacement: "/agent.sock", want: "dedicated parent directory"},
		{name: "shared parent", old: "/run/consumers/second/agent.sock", replacement: "/run/consumers/first/other.sock", want: "parent directory overlaps"},
		{name: "nested parent", old: "/run/consumers/second/agent.sock", replacement: "/run/consumers/first/nested/agent.sock", want: "parent directory overlaps"},
		{name: "parent contains upstream", old: "/run/consumers/first/agent.sock", replacement: "/run/consumer.sock", want: "must not contain the upstream socket"},
		{name: "negative access group", old: "access-group: 1200", replacement: "access-group: -1", want: "between 0 and 4294967294"},
		{name: "reserved access group", old: "access-group: 1200", replacement: "access-group: 4294967295", want: "between 0 and 4294967294"},
		{name: "string access group", old: "access-group: 1200", replacement: `access-group: "1200"`, want: "must be an integer"},
		{name: "fingerprint prefix", old: fingerprint, replacement: strings.TrimPrefix(fingerprint, "SHA256:"), want: "SHA256: prefix"},
		{name: "fingerprint padding", old: fingerprint, replacement: fingerprint + "=", want: "canonical unpadded base64"},
		{name: "fingerprint digest length", old: fingerprint, replacement: "SHA256:AA", want: "32-byte SHA-256 digest"},
		{name: "duplicate fingerprint", old: "      - " + fingerprint, replacement: "      - " + fingerprint + "\n      - " + fingerprint, want: "duplicates consumers[0].fingerprints[0]"},
		{name: "invalid duration", old: "connect: 5s", replacement: "connect: soon", want: "timeouts.connect"},
		{name: "short timeout below bound", old: "connect: 5s", replacement: "connect: 99ms", want: "between 100ms and 30s"},
		{name: "short timeout above bound", old: "replay: 5s", replacement: "replay: 31s", want: "between 100ms and 30s"},
		{name: "sign timeout below bound", old: "sign: 2m", replacement: "sign: 999ms", want: "between 1s and 10m0s"},
		{name: "sign timeout above bound", old: "sign: 2m", replacement: "sign: 11m", want: "between 1s and 10m0s"},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			input := test.input
			if input == "" && test.old != "" {
				input = strings.Replace(valid, test.old, test.replacement, 1)
			} else if test.old != "" {
				input = strings.Replace(input, test.old, test.replacement, 1)
			}
			_, err := Parse([]byte(input))
			if err == nil {
				t.Fatal("Parse() error = nil")
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Parse() error = %q, want substring %q", err, test.want)
			}
		})
	}
}

func TestParseRejectsOversizedDocumentBeforeYAMLDecoding(t *testing.T) {
	t.Parallel()

	_, err := Parse(make([]byte, MaximumDocumentBytes+1))
	if err == nil || !strings.Contains(err.Error(), "exceeds the supported size") {
		t.Fatalf("Parse() error = %v", err)
	}
}

func TestParseConsumerNameUnicodeLimit(t *testing.T) {
	t.Parallel()

	configuration := func(name string) string {
		return fmt.Sprintf(`upstream: /run/upstream/agent.sock
consumers:
  - name: %s
    socket: /run/consumers/first/agent.sock
    fingerprints: []
timeouts:
  connect: 5s
  list: 5s
  replay: 5s
  sign: 2m
`, name)
	}
	accepted := strings.Repeat("界", MaximumConsumerNameCharacters)
	parsed, err := Parse([]byte(configuration(accepted)))
	if err != nil {
		t.Fatalf("Parse() rejected %d multibyte characters: %v", MaximumConsumerNameCharacters, err)
	}
	if parsed.Consumers[0].Name != accepted {
		t.Fatal("Parse() did not preserve the accepted display name")
	}
	_, err = Parse([]byte(configuration(accepted + "界")))
	if err == nil || !strings.Contains(err.Error(), "at most 256 Unicode characters") {
		t.Fatalf("Parse() oversized-name error = %v", err)
	}
	invalid := Config{
		Upstream: "/run/upstream/agent.sock", Timeouts: DefaultTimeouts(),
		Consumers: []Consumer{{Name: string([]byte{0xff}), Socket: "/run/consumers/first/agent.sock"}},
	}
	if err := Validate(invalid); err == nil || !strings.Contains(err.Error(), "Unicode characters") {
		t.Fatalf("Validate() invalid-UTF-8 error = %v", err)
	}
}

func TestParseAcceptsPositiveGoDurationSpellings(t *testing.T) {
	t.Parallel()

	spellings := []string{
		"100ms",
		"30s",
		"+5s",
		".5s",
		"1.s",
		"500000µs",
		"500000μs",
	}
	for _, spelling := range spellings {
		spelling := spelling
		t.Run(spelling, func(t *testing.T) {
			t.Parallel()
			configuration, err := Parse([]byte(testConfigurationWithTimeouts(spelling, "1s", "1s", "1s")))
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			want, err := time.ParseDuration(spelling)
			if err != nil {
				t.Fatalf("time.ParseDuration(%q) error = %v", spelling, err)
			}
			if configuration.Timeouts.Connect != want {
				t.Fatalf("Parse().Timeouts.Connect = %s, want %s", configuration.Timeouts.Connect, want)
			}
		})
	}
}

func TestParseAcceptsTimeoutBounds(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                  string
		connect, list, replay string
		sign                  string
	}{
		{name: "minimum", connect: "100ms", list: "100ms", replay: "100ms", sign: "1s"},
		{name: "maximum", connect: "30s", list: "30s", replay: "30s", sign: "10m"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := Parse([]byte(testConfigurationWithTimeouts(test.connect, test.list, test.replay, test.sign))); err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
		})
	}
}

func TestValidateRejectsReservedProgrammaticAccessGroup(t *testing.T) {
	t.Parallel()

	reserved := ^uint32(0)
	configuration := Config{
		Upstream: "/run/upstream/agent.sock",
		Consumers: []Consumer{{
			Name: "consumer", Socket: "/run/consumers/first/agent.sock", AccessGroup: &reserved,
		}},
		Timeouts: DefaultTimeouts(),
	}
	if err := Validate(configuration); err == nil || !strings.Contains(err.Error(), "access-group") {
		t.Fatalf("Validate() error = %v, want access-group error", err)
	}
}

func TestLoadIncludesConfigurationPathInErrors(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(path, []byte("unexpected: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), "unexpected") {
		t.Fatalf("Load() error = %v, want path and field", err)
	}
}

func testFingerprint(value byte) string {
	digest := make([]byte, 32)
	for index := range digest {
		digest[index] = value
	}
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(digest)
}

func testConfigurationWithTimeouts(connect, list, replay, sign string) string {
	return fmt.Sprintf(`upstream: /run/upstream/agent.sock
consumers: []
timeouts:
  connect: %s
  list: %s
  replay: %s
  sign: %s
`, connect, list, replay, sign)
}
