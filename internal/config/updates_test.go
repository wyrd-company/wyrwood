// ---
// relationships:
//   verifies: configuration
// ---

package config

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/wyrd-company/wyrwood/internal/schematest"
	"gopkg.in/yaml.v3"
)

func TestControllerUpdateCheckDefaultsAndOverrides(t *testing.T) {
	for _, sample := range []struct {
		suffix            string
		enabled           bool
		interval, timeout time.Duration
	}{
		{"", false, 24 * time.Hour, 10 * time.Second},
		{"update-checks:\n  enabled: true\n", true, 24 * time.Hour, 10 * time.Second},
		{"update-checks:\n  enabled: true\n  interval: 37m\n  timeout: 7s\n", true, 37 * time.Minute, 7 * time.Second},
		{"update-checks:\n  interval: 48h\n  timeout: 2m\n", false, 48 * time.Hour, 2 * time.Minute},
	} {
		document := []byte(minimalController + sample.suffix)
		parsed, err := ParseController(document)
		if err != nil {
			t.Fatal(err)
		}
		if parsed.UpdateChecks != (UpdateChecks{Enabled: sample.enabled, Interval: sample.interval, Timeout: sample.timeout}) {
			t.Fatalf("settings = %#v", parsed.UpdateChecks)
		}
		var data any
		if err := yaml.Unmarshal(document, &data); err != nil {
			t.Fatal(err)
		}
		value, _ := json.Marshal(data)
		if err := schematest.Validate(schematest.Compile(t, schematest.ControllerConfiguration), value); err != nil {
			t.Fatal(err)
		}
	}
}

func TestControllerRejectsNonPositiveUpdateCheckDurations(t *testing.T) {
	for _, field := range []string{"interval", "timeout"} {
		for _, value := range []string{"0s", "-1s", "never", "999999999999999999999h", "''"} {
			if _, err := ParseController([]byte(minimalController + "update-checks:\n  " + field + ": " + value + "\n")); !errors.Is(err, ErrInvalid) {
				t.Errorf("%s=%s: %v", field, value, err)
			}
		}
	}
}
