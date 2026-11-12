// ---
// relationships:
//   verifies: agent-controller-protocol
// ---

package protocol

import (
	"bytes"
	"errors"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/wyrd-company/wyrwood/internal/policy"
	"github.com/wyrd-company/wyrwood/internal/schematest"
)

// formerNameRule is the rule a container name met to name a consumer directory
// before the rule moved to this package, kept here as the reference.
var formerNameRule = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,254}$`)

func formerValidName(name string) bool {
	return formerNameRule.MatchString(name) && name != "." && name != ".."
}

func directoryNameCorpus() []string {
	corpus := []string{"", ".", "..", "...", ".a", "a.", "a", "A", "0", "web", "shop-web_1.2", "-web", "_web", "a/b", "/a", "a/", "a\\b",
		"a b", "a\x00", "á", "web\n", strings.Repeat("a", 254), strings.Repeat("a", 255), strings.Repeat("a", 256), strings.Repeat("a", 512),
		"a" + strings.Repeat(".", 254), "a/" + strings.Repeat("b", 300)}
	for _, character := range "!\"#$%&'()*+,:;<=>?@[]^`{|}~" {
		corpus = append(corpus, "a"+string(character))
	}
	return corpus
}

// The directory name rule is the rule a container name met before: a name key
// and a typed directory name accept the same names.
func TestDirectoryNameRuleEqualsTheFormerContainerNameRule(t *testing.T) {
	for _, name := range directoryNameCorpus() {
		if got, want := ValidDirectoryName(name), formerValidName(name); got != want {
			t.Errorf("ValidDirectoryName(%q) = %v, the former rule says %v", name, got, want)
		}
	}
}

// Each refusal is named, so that a form and a test can tell them apart.
func TestDirectoryNameRefusalsAreNamed(t *testing.T) {
	for name, want := range map[string]error{
		"":                       ErrDirectoryNameEmpty,
		"a/b":                    ErrDirectoryNameSeparator,
		"/":                      ErrDirectoryNameSeparator,
		"../web":                 ErrDirectoryNameSeparator,
		".":                      ErrDirectoryNameDots,
		"..":                     ErrDirectoryNameDots,
		strings.Repeat("a", 256): ErrDirectoryNameLength,
		"-web":                   ErrDirectoryNameCharacters,
		"web app":                ErrDirectoryNameCharacters,
		".hidden":                ErrDirectoryNameCharacters,
	} {
		if err := ValidateDirectoryName(name); !errors.Is(err, want) {
			t.Errorf("ValidateDirectoryName(%q) = %v, want %v", name, err, want)
		}
	}
	for _, name := range []string{"a", "shop-web_1.2", strings.Repeat("a", 255)} {
		if err := ValidateDirectoryName(name); err != nil {
			t.Errorf("ValidateDirectoryName(%q) = %v", name, err)
		}
	}
}

func directoryPolicySet(key Key, directory string) PolicySet {
	effective := policy.New("teal", `path "kv/*" {}`).Runtime(policy.DefaultSettings())
	return PolicySet{OpenBao: OpenBao{Address: "http://127.0.0.1:8200"}, Bindings: []Binding{{
		Binding: "b-1", Key: key, Directory: directory, Policy: effective, Assignment: effective.Identity(),
	}}}
}

// A binding whose key is not name carries its directory name; the Go types and
// the schema agree on which sets are valid.
func TestBindingDirectoryRoundTripsAndValidatesAgainstSchema(t *testing.T) {
	schema := schematest.Compile(t, schematest.AgentControllerMessage)
	compose := Key{Kind: KeyCompose, Value: "shop/web"}
	for _, directory := range []string{"shop-web", strings.Repeat("a", 255)} {
		set := directoryPolicySet(compose, directory)
		line, err := Encode(set)
		if err != nil {
			t.Fatal(err)
		}
		if err := schematest.Validate(schema, line); err != nil {
			t.Fatalf("%s does not validate: %v", line, err)
		}
		decoded, err := Decode(bytes.TrimSuffix(line, []byte("\n")))
		if err != nil || !reflect.DeepEqual(decoded, Message(set)) {
			t.Fatalf("round trip = %#v, %v", decoded, err)
		}
	}
	// A binding without a directory encodes as it did before the field existed.
	line, err := Encode(directoryPolicySet(compose, ""))
	if err != nil || bytes.Contains(line, []byte(`"directory"`)) {
		t.Fatalf("a binding without a directory = %s, %v", line, err)
	}
	for name, set := range map[string]PolicySet{
		"name-key":  directoryPolicySet(Key{Kind: KeyName, Value: "web"}, "other"),
		"separator": directoryPolicySet(compose, "a/b"),
		"dots":      directoryPolicySet(compose, ".."),
		"length":    directoryPolicySet(compose, strings.Repeat("a", 256)),
		"character": directoryPolicySet(compose, "-web"),
	} {
		t.Run(name, func(t *testing.T) {
			if err := set.Validate(); err == nil {
				t.Fatal("Validate() accepted the set")
			}
			// Encode refuses an invalid message, so the schema is checked on its own.
			raw, err := Encode(directoryPolicySet(compose, "valid"))
			if err != nil {
				t.Fatal(err)
			}
			bad := bytes.Replace(raw, []byte(`"directory":"valid"`), []byte(`"directory":"`+set.Bindings[0].Directory+`"`), 1)
			if set.Bindings[0].Key.Kind == KeyName {
				bad = bytes.Replace(bad, []byte(`{"kind":"compose","value":"shop/web"}`), []byte(`{"kind":"name","value":"web"}`), 1)
			}
			if bytes.Equal(bad, raw) {
				t.Fatal("the invalid line was not built")
			}
			if err := schematest.Validate(schema, bad); err == nil {
				t.Fatalf("the schema accepted %s", bad)
			}
			if _, err := Decode(bytes.TrimSuffix(bad, []byte("\n"))); !errors.Is(err, ErrInvalid) {
				t.Fatalf("Decode() = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestPreparedDirectoryNamesTheDirectoryBeforeAContainer(t *testing.T) {
	for _, test := range []struct {
		binding Binding
		want    string
	}{
		{Binding{Key: Key{Kind: KeyName, Value: "web"}}, "web"},
		{Binding{Key: Key{Kind: KeyCompose, Value: "shop/web"}, Directory: "shop-web"}, "shop-web"},
		{Binding{Key: Key{Kind: KeyDevcontainer, Value: "/src/app"}}, ""},
	} {
		if got := test.binding.PreparedDirectory(); got != test.want {
			t.Errorf("PreparedDirectory(%+v) = %q, want %q", test.binding, got, test.want)
		}
	}
}
