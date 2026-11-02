// ---
// relationships:
//   verifies: composable-policy-bindings
// ---

package policy

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

func TestOpenBaoIdentityFollowsTheGeneration(t *testing.T) {
	for _, row := range []struct {
		generation int
		want       string
	}{{0, "wyrwood-sample"}, {1, "wyrwood-sample"}, {2, "wyrwood-sample--2"}, {17, "wyrwood-sample--17"}} {
		document := New("sample", StarterHCL)
		document.Generation = row.generation
		if got := document.OpenBaoPolicyName(); got != row.want {
			t.Errorf("generation %d: OpenBaoPolicyName() = %q, want %q", row.generation, got, row.want)
		}
		effective, err := Compose([]Policy{document}, DefaultSettings())
		if err != nil {
			t.Fatal(err)
		}
		if got := effective.OpenBaoPolicies(); !slices.Equal(got, []string{row.want}) {
			t.Errorf("generation %d: OpenBaoPolicies() = %v, want %s", row.generation, got, row.want)
		}
		if err := effective.Validate(); err != nil {
			t.Errorf("generation %d: Validate() = %v", row.generation, err)
		}
	}
}

// No policy name can spell another policy's later generation.
func TestNoPolicyNameSpellsAGeneration(t *testing.T) {
	for _, name := range []string{"sample--2", "sample--", "--2"} {
		if ValidName(name) {
			t.Errorf("ValidName(%q) = true", name)
		}
	}
}

// An assignment that names only first uses has the bytes it had before
// generations existed, so that an upgrade reissues no credential.
func TestFirstUseAssignmentCarriesNoGeneration(t *testing.T) {
	first := New("sample", StarterHCL)
	first.Revision = 3
	first.Generation = 1
	effective, err := Compose([]Policy{first}, DefaultSettings())
	if err != nil {
		t.Fatal(err)
	}
	unset := first
	unset.Generation = 0
	same, err := Compose([]Policy{unset}, DefaultSettings())
	if err != nil {
		t.Fatal(err)
	}
	if effective.Identity() != same.Identity() {
		t.Fatal("the first generation changed the assignment identity")
	}
	encoded, err := json.Marshal(effective)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "generation") {
		t.Fatalf("first-use assignment names a generation: %s", encoded)
	}
	later := first
	later.Generation = 2
	reused, err := Compose([]Policy{later}, DefaultSettings())
	if err != nil {
		t.Fatal(err)
	}
	if reused.Identity() == effective.Identity() {
		t.Fatal("a later generation kept the assignment identity")
	}
	single := first.Runtime(DefaultSettings())
	if single.Sources[0].Generation != 0 {
		t.Fatalf("Runtime source generation = %d, want 0", single.Sources[0].Generation)
	}
	later.Generation = 5
	if got := later.Runtime(DefaultSettings()).OpenBaoPolicies(); !slices.Equal(got, []string{"wyrwood-sample--5"}) {
		t.Fatalf("Runtime OpenBaoPolicies() = %v", got)
	}
}

// The generation belongs to the store. A document never carries one, and a
// document cannot supply one.
func TestAPolicyDocumentHasNoGeneration(t *testing.T) {
	document := New("sample", StarterHCL)
	document.Generation = 4
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "generation") {
		t.Fatalf("document names a generation: %s", encoded)
	}
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Generation != 0 {
		t.Fatalf("decoded generation = %d", decoded.Generation)
	}
	crafted := strings.Replace(string(encoded), `"name":`, `"generation":9,"name":`, 1)
	if _, err := Decode([]byte(crafted)); err == nil {
		t.Fatal("a document with a generation field was accepted")
	}
}

func TestEffectiveRefusesAnInvalidGeneration(t *testing.T) {
	for _, generation := range []int{-1, 1} {
		effective := New("sample", StarterHCL).Runtime(DefaultSettings())
		effective.Sources[0].Generation = generation
		if err := effective.Validate(); err == nil {
			t.Errorf("generation %d accepted", generation)
		}
	}
}
