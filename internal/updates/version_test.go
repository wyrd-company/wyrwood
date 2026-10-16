// ---
// relationships:
//   verifies: web-interface
// ---

package updates

import "testing"

func TestBuildVersionsUseSemVerPrecedence(t *testing.T) {
	for _, sample := range []struct {
		current, other string
		older          bool
	}{
		{"3.9.0", "3.10.0", true},
		{"3.10.0", "3.9.0", false},
		{"9.0.0", "10.0.0", true},
		{"3.4.5", "3.4.5", false},
		{"3.4.5-rc.9", "3.4.5-rc.10", true},
		{"3.4.5-rc.1", "3.4.5", true},
		{"3.4.5", "3.4.5-rc.1", false},
		{"3.4.5+first", "3.4.5+second", false},
		{"v3.4.5", "3.4.6", true},
		{"3.4.5", "v3.4.6", true},
		{"dev", "3.4.5", false},
		{"3.4.5", "dev", false},
		{"", "3.4.5", false},
		{"3.4", "3.4.5", false},
		{"3.04.5", "3.4.6", false},
		{"3.4.5-rc.01", "3.4.6", false},
		{"999999999999999999999.0.0", "1000000000000000000000.0.0", true},
	} {
		t.Run(sample.current+"_"+sample.other, func(t *testing.T) {
			if got := Older(sample.current, sample.other); got != sample.older {
				t.Fatalf("Older(%q,%q)=%t, want %t", sample.current, sample.other, got, sample.older)
			}
		})
	}
}
