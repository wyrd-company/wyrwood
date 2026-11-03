// ---
// relationships:
//   verifies: operator-interface
// ---

package operator

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
)

func TestUserRoundTripsAndNeverReadsAsAHostname(t *testing.T) {
	hostname := regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,62})(\.[A-Za-z0-9]([A-Za-z0-9-]{0,62}))*$`)
	user := User("sample-key")
	if label, ok := ParseUser(user); !ok || label != "sample-key" {
		t.Fatalf("ParseUser(%q) = %q, %v", user, label, ok)
	}
	if hostname.MatchString(user) {
		t.Fatalf("%q reads as an agent hostname", user)
	}
	for _, candidate := range []string{"sample-key", "operator", "operator:", "operator:not a label", "operator:-leading", "operator:" + strings.Repeat("a", 65), "Operator:sample"} {
		if label, ok := ParseUser(candidate); ok {
			t.Fatalf("ParseUser(%q) = %q", candidate, label)
		}
	}
}

func TestGrantAllowsOnlyWhatItLists(t *testing.T) {
	grant := Grant{Agents: []string{"host-a"}, Policies: []string{"allowed"}, Actions: []Action{ActionRead}}
	for name, check := range map[string]bool{
		"listed agent":          grant.AllowsAgent("host-a"),
		"listed policy":         grant.AllowsPolicy("allowed"),
		"listed action":         grant.Can(ActionRead),
		"covers":                grant.Covers("host-a", []string{"allowed"}),
		"covers a bare binding": grant.Covers("host-a", nil),
		"all names":             Grant{Agents: []string{AllNames}}.AllowsAgent("any-host"),
	} {
		if !check {
			t.Errorf("%s: refused", name)
		}
	}
	for name, check := range map[string]bool{
		"other agent":         grant.AllowsAgent("host-b"),
		"other policy":        grant.AllowsPolicy("other"),
		"other action":        grant.Can(ActionBind),
		"other agent binding": grant.Covers("host-b", []string{"allowed"}),
		"one policy outside":  grant.Covers("host-a", []string{"allowed", "other"}),
		"empty list":          Grant{}.AllowsAgent("host-a"),
		"literal star name":   Grant{Agents: []string{"host-a"}}.AllowsAgent(AllNames),
		"star among names":    Grant{Agents: []string{AllNames, "host-a"}}.AllowsAgent("host-b"),
	} {
		if check {
			t.Errorf("%s: allowed", name)
		}
	}
}

func TestParseKey(t *testing.T) {
	key, err := ParseKey("devcontainer:/workspaces/sample|.devcontainer/devcontainer.json")
	if err != nil || key.Kind != KeyDevcontainer || key.Value != "/workspaces/sample|.devcontainer/devcontainer.json" {
		t.Fatalf("ParseKey() = %+v, %v", key, err)
	}
	for _, text := range []string{"", "name", "name:", "other:value", ":value"} {
		if _, err := ParseKey(text); err == nil {
			t.Errorf("ParseKey(%q) succeeded", text)
		}
	}
}

func TestErrorMatchesItsCodeOnly(t *testing.T) {
	err := error(&Error{Code: CodeOutsideGrant, Message: "sample"})
	if !errors.Is(err, ErrOutsideGrant) || errors.Is(err, ErrNotFound) {
		t.Fatalf("errors.Is(%v) is wrong", err)
	}
	if !errors.Is(&Error{Code: "from-a-newer-controller"}, ErrFailed) {
		t.Fatal("an unknown code does not match ErrFailed")
	}
	for code := range codeErrors {
		if errors.Is(&Error{Code: code}, ErrFailed) != (code == CodeFailed) {
			t.Errorf("code %s matches ErrFailed", code)
		}
	}
}

func TestLoadOrCreateKeyIsOwnerOnlyAndStable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "operator_key")
	first, created, err := LoadOrCreateKey(path)
	if err != nil || !created {
		t.Fatalf("LoadOrCreateKey() = %v, %v", created, err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("key file = %v, %v", info, err)
	}
	second, created, err := LoadOrCreateKey(path)
	if err != nil || created || ssh.FingerprintSHA256(first.PublicKey()) != ssh.FingerprintSHA256(second.PublicKey()) {
		t.Fatalf("second load = %v, %v", created, err)
	}
	if err := os.WriteFile(path, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadOrCreateKey(path); !errors.Is(err, ErrLoginState) {
		t.Fatalf("unreadable key = %v", err)
	}
}

func addAgentKey(t *testing.T, keyring sshagent.Agent, comment string) ssh.PublicKey {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := keyring.Add(sshagent.AddedKey{PrivateKey: private, Comment: comment}); err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestSelectAgentKey(t *testing.T) {
	keyring := sshagent.NewKeyring()
	wanted := addAgentKey(t, keyring, "wanted-name")
	other := addAgentKey(t, keyring, "other-name")
	addAgentKey(t, keyring, "shared-name")
	addAgentKey(t, keyring, "shared-name")
	// A name that reads as another key's fingerprint must not win over the key.
	addAgentKey(t, keyring, ssh.FingerprintSHA256(other))
	authorized := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(wanted)))
	for name, selection := range map[string]string{
		"fingerprint":        ssh.FingerprintSHA256(wanted),
		"public key":         authorized,
		"public key comment": authorized + " any-comment",
		"name":               "wanted-name",
	} {
		t.Run(name, func(t *testing.T) {
			signer, err := SelectAgentKey(keyring, selection)
			if err != nil || ssh.FingerprintSHA256(signer.PublicKey()) != ssh.FingerprintSHA256(wanted) {
				t.Fatalf("SelectAgentKey(%q) = %v, %v", selection, signer, err)
			}
			if _, err := signer.Sign(rand.Reader, []byte("sample")); err != nil {
				t.Fatal(err)
			}
		})
	}
	if signer, err := SelectAgentKey(keyring, ssh.FingerprintSHA256(other)); err != nil || ssh.FingerprintSHA256(signer.PublicKey()) != ssh.FingerprintSHA256(other) {
		t.Fatalf("a fingerprint selected another key: %v, %v", signer, err)
	}
	for name, selection := range map[string]string{"absent": "missing-name", "ambiguous": "shared-name", "empty": ""} {
		t.Run(name, func(t *testing.T) {
			if _, err := SelectAgentKey(keyring, selection); !errors.Is(err, ErrKeySelection) {
				t.Fatalf("SelectAgentKey(%q) = %v", selection, err)
			}
		})
	}
}

func TestDialAgentNeedsASocket(t *testing.T) {
	if _, _, err := DialAgent(""); !errors.Is(err, ErrKeySelection) {
		t.Fatalf("DialAgent() = %v", err)
	}
	if _, _, err := DialAgent(filepath.Join(t.TempDir(), "absent.sock")); !errors.Is(err, ErrKeySelection) {
		t.Fatalf("DialAgent() = %v", err)
	}
}

func TestProfileRoundTripsWithOwnerOnlyMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "operator.json")
	want := Profile{URL: "ssh://sample:22", HostKey: "SHA256:sample", Label: "sample-key", KeyFile: "/tmp/sample"}
	if err := SaveProfile(path, want); err != nil {
		t.Fatal(err)
	}
	got, err := LoadProfile(path)
	if err != nil || got != want {
		t.Fatalf("LoadProfile() = %+v, %v", got, err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("profile = %v, %v", info, err)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != 1 {
		t.Fatalf("directory holds a temporary file: %v, %v", entries, err)
	}
	if err := os.WriteFile(path, []byte(`{"url":"ssh://sample:22"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadProfile(path); !errors.Is(err, ErrLoginState) {
		t.Fatalf("a profile with no host key = %v", err)
	}
}

func TestLoginProfileKeepsAnUnreadableProfile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "operator.json")
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoginProfile(context.Background(), path, LoginOptions{URL: "ssh://127.0.0.1:1"}); !errors.Is(err, ErrLoginState) {
		t.Fatalf("LoginProfile() = %v", err)
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "not json" {
		t.Fatalf("the profile changed: %q, %v", data, err)
	}
}

func TestReadLineIsBounded(t *testing.T) {
	reader := bufio.NewReaderSize(strings.NewReader("short\n"+strings.Repeat("a", 64)+"\n"), 16)
	line, err := ReadLine(reader, 32)
	if err != nil || string(line) != "short" {
		t.Fatalf("ReadLine() = %q, %v", line, err)
	}
	if _, err := ReadLine(reader, 32); err == nil {
		t.Fatal("an oversized line was read")
	}
}
