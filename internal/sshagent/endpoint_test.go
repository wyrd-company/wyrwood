// ---
// relationships:
//   verifies: ssh-agent-endpoint
// ---

package sshagent

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openbao/openbao/api/v2"
	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"

	"github.com/wyrd-company/wyrwood/internal/binding"
	"github.com/wyrd-company/wyrwood/internal/events"
	"github.com/wyrd-company/wyrwood/internal/openbao"
	"github.com/wyrd-company/wyrwood/internal/openbao/baotest"
	"github.com/wyrd-company/wyrwood/internal/policy"
	"github.com/wyrd-company/wyrwood/internal/protocol"
)

var apiTokenRequest = api.TokenCreateRequest{Policies: []string{"wyrwood-teal"}, TTL: "1h"}

type fixture struct {
	socket string
	mu     sync.Mutex
	view   binding.View
	events []events.Event
}

func (fixture *fixture) lookup() (binding.View, bool) {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	return fixture.view, true
}

func (fixture *fixture) record(event events.Event) {
	if err := event.Validate(); err != nil {
		panic(err)
	}
	fixture.mu.Lock()
	fixture.events = append(fixture.events, event)
	fixture.mu.Unlock()
}

func (fixture *fixture) operations() map[events.Operation]int {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	counts := map[events.Operation]int{}
	for _, event := range fixture.events {
		counts[event.Operation]++
	}
	return counts
}

func setup(t *testing.T) (*baotest.Server, *fixture) {
	t.Helper()
	bao := baotest.Start(t)
	bao.CreateTransitKey(t, "teal-ed", "ed25519")
	bao.CreateTransitKey(t, "teal-rsa", "rsa-2048")
	bao.CreateSSHRole(t, "teal-hosts", "root", "30m")
	hcl := `
path "transit/keys/teal-*" { capabilities = ["read"] }
path "transit/sign/teal-*" { capabilities = ["update"] }
path "ssh/sign/teal-hosts" { capabilities = ["update"] }
`
	if err := bao.Root.Sys().PutPolicy("wyrwood-teal", hcl); err != nil {
		t.Fatal(err)
	}
	secret, err := bao.Root.Auth().Token().Create(&apiTokenRequest)
	if err != nil {
		t.Fatal(err)
	}
	client, err := openbao.NewClient(openbao.Endpoint{Address: bao.Address, Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	document := policy.New("teal", hcl)
	document.SSH = &policy.SSH{TransitKeys: []string{"teal-ed", "teal-rsa"}, CARoles: []string{"teal-hosts"}}
	fixture := &fixture{socket: filepath.Join(t.TempDir(), "ssh-agent.sock")}
	fixture.view = binding.View{
		ID: "b-1", ContainerKey: "name:web", Policy: document, OpenBao: protocol.OpenBao{Address: bao.Address},
		Mounts: binding.Mounts{Transit: "transit", SSH: "ssh"}, Client: client,
		Token: openbao.NewToken(secret.Auth.ClientToken, time.Hour), HasToken: true,
	}
	listener, err := net.Listen("unix", fixture.socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go New(10*time.Second).Serve(listener, fixture.lookup, fixture.record)
	return bao, fixture
}

func dial(t *testing.T, socket string) sshagent.ExtendedAgent {
	t.Helper()
	connection, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	return sshagent.NewClient(connection)
}

func TestIdentitiesSigningAndPolicyChanges(t *testing.T) {
	bao, fixture := setup(t)
	client := dial(t, fixture.socket)
	keys, err := client.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 3 || keys[0].Comment != "teal-ed" || keys[1].Comment != "teal-rsa" || keys[2].Comment != "teal-hosts" {
		t.Fatalf("List() = %v", keys)
	}
	data := make([]byte, 64)
	_, _ = rand.Read(data)

	edKey, _ := ssh.ParsePublicKey(keys[0].Blob)
	signature, err := client.Sign(edKey, data)
	if err != nil || edKey.Verify(data, signature) != nil {
		t.Fatalf("ed25519 Sign() = %v", err)
	}
	rsaKey, _ := ssh.ParsePublicKey(keys[1].Blob)
	for flags, format := range map[sshagent.SignatureFlags]string{
		sshagent.SignatureFlagRsaSha256: ssh.KeyAlgoRSASHA256, sshagent.SignatureFlagRsaSha512: ssh.KeyAlgoRSASHA512,
	} {
		signature, err := client.SignWithFlags(rsaKey, data, flags)
		if err != nil || signature.Format != format || rsaKey.Verify(data, signature) != nil {
			t.Fatalf("RSA SignWithFlags(%d) = %v, %v", flags, signature, err)
		}
	}
	if _, err := client.Sign(rsaKey, data); err == nil {
		t.Fatal("RSA SHA-1 signature was produced")
	}

	certificateKey, _ := ssh.ParsePublicKey(keys[2].Blob)
	certificate := certificateKey.(*ssh.Certificate)
	caKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(bao.CAPublicKey(t)))
	if err != nil {
		t.Fatal(err)
	}
	checker := ssh.CertChecker{IsUserAuthority: func(key ssh.PublicKey) bool { return bytes.Equal(key.Marshal(), caKey.Marshal()) }}
	if err := checker.CheckCert("root", certificate); err != nil {
		t.Fatalf("certificate does not check: %v", err)
	}
	signature, err = client.Sign(certificateKey, data)
	if err != nil || certificate.Key.Verify(data, signature) != nil {
		t.Fatalf("certificate Sign() = %v", err)
	}
	again, _ := client.List()
	if !bytes.Equal(again[2].Blob, keys[2].Blob) {
		t.Fatal("certificate was reissued before it needed to be")
	}

	for name, operation := range map[string]func() error{
		"add":        func() error { return client.Add(sshagent.AddedKey{PrivateKey: nil}) },
		"remove":     func() error { return client.Remove(edKey) },
		"remove-all": client.RemoveAll,
		"lock":       func() error { return client.Lock([]byte("x")) },
	} {
		if err := operation(); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if _, err := client.Extension("unknown@example.com", nil); err == nil {
		t.Fatal("unknown extension was accepted")
	}

	fixture.mu.Lock()
	changed := fixture.view.Policy.Clone()
	changed.SSH.TransitKeys = []string{"teal-rsa"}
	fixture.view.Policy = changed
	fixture.mu.Unlock()
	keys, err = client.List()
	if err != nil || len(keys) != 2 || keys[0].Comment != "teal-rsa" {
		t.Fatalf("List() after policy change = %v, %v", keys, err)
	}
	if _, err := client.Sign(edKey, data); err == nil {
		t.Fatal("removed identity still signs on an open connection")
	}

	fixture.mu.Lock()
	fixture.view.HasToken = false
	fixture.mu.Unlock()
	if keys, err := client.List(); err != nil || len(keys) != 0 {
		t.Fatalf("List() without token = %v, %v", keys, err)
	}
	counts := fixture.operations()
	if counts[events.OperationSSHList] < 4 || counts[events.OperationSSHSign] < 5 || counts[events.OperationSSHCertificate] != 1 {
		t.Fatalf("event counts = %v", counts)
	}
	for _, event := range fixture.events {
		if event.Operation == events.OperationSSHSign && event.Fingerprint == "" {
			t.Fatalf("sign event without fingerprint: %#v", event)
		}
	}
}

func TestCertificateReissueTiming(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	entry := &certificate{certificate: &ssh.Certificate{ValidAfter: uint64(now.Unix()), ValidBefore: uint64(now.Add(30 * time.Minute).Unix())}}
	if entry.needsReissue(now.Add(19 * time.Minute)) {
		t.Fatal("reissued with more than a third remaining")
	}
	if !entry.needsReissue(now.Add(21 * time.Minute)) {
		t.Fatal("not reissued with less than a third remaining")
	}
}

// TestOpenSSHAcceptsSignatures drives real OpenSSH tools against the
// endpoint: ssh-add lists identities, ssh-keygen signs and verifies, and ssh
// authenticates to a local sshd with a Transit key and with a certificate.
func TestOpenSSHAcceptsSignatures(t *testing.T) {
	for _, tool := range []string{"ssh", "ssh-add", "ssh-keygen", "/usr/sbin/sshd"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not available", tool)
		}
	}
	bao, fixture := setup(t)
	environment := append(os.Environ(), "SSH_AUTH_SOCK="+fixture.socket)
	run := func(name string, arguments ...string) string {
		t.Helper()
		command := exec.Command(name, arguments...)
		command.Env = environment
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("%s %v: %v\n%s", name, arguments, err, output)
		}
		return string(output)
	}
	listing := run("ssh-add", "-L")
	lines := strings.Split(strings.TrimSpace(listing), "\n")
	if len(lines) != 3 || !strings.HasSuffix(lines[0], " teal-ed") || !strings.Contains(lines[2], "-cert-v01@openssh.com") {
		t.Fatalf("ssh-add -L = %s", listing)
	}
	directory := t.TempDir()
	for index, line := range lines[:2] {
		publicKey := filepath.Join(directory, fmt.Sprintf("key%d.pub", index))
		message := filepath.Join(directory, fmt.Sprintf("message%d", index))
		_ = os.WriteFile(publicKey, []byte(line+"\n"), 0o600)
		_ = os.WriteFile(message, []byte("signed through OpenBao"), 0o600)
		run("ssh-keygen", "-Y", "sign", "-n", "file", "-f", publicKey, message)
		fields := strings.Fields(line)
		allowed := filepath.Join(directory, fmt.Sprintf("allowed%d", index))
		_ = os.WriteFile(allowed, []byte("signer@example "+fields[0]+" "+fields[1]+"\n"), 0o600)
		command := exec.Command("ssh-keygen", "-Y", "verify", "-f", allowed, "-I", "signer@example", "-n", "file", "-s", message+".sig")
		command.Stdin = bytes.NewReader([]byte("signed through OpenBao"))
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("ssh-keygen -Y verify: %v\n%s", err, output)
		}
	}

	if os.Geteuid() != 0 {
		t.Skip("sshd test requires root")
	}
	port := freePort(t)
	hostKey := filepath.Join(directory, "host_ed25519")
	run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", hostKey)
	caFile := filepath.Join(directory, "ca.pub")
	_ = os.WriteFile(caFile, []byte(bao.CAPublicKey(t)), 0o644)
	authorized := filepath.Join(directory, "authorized_keys")
	_ = os.WriteFile(authorized, []byte(lines[0]+"\n"), 0o600)
	configuration := filepath.Join(directory, "sshd_config")
	_ = os.WriteFile(configuration, []byte(fmt.Sprintf(`Port %d
ListenAddress 127.0.0.1
HostKey %s
PidFile %s/sshd.pid
AuthorizedKeysFile %s
TrustedUserCAKeys %s
PermitRootLogin prohibit-password
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
StrictModes no
`, port, hostKey, directory, authorized, caFile)), 0o600)
	_ = os.MkdirAll("/run/sshd", 0o755)
	server := exec.Command("/usr/sbin/sshd", "-D", "-e", "-f", configuration)
	var serverLog bytes.Buffer
	server.Stderr = &serverLog
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Process.Kill(); _ = server.Wait() })
	waitForPort(t, port)
	knownHosts := filepath.Join(directory, "known_hosts")
	for _, identity := range []string{lines[0], lines[2]} {
		identityFile := filepath.Join(directory, "identity.pub")
		_ = os.WriteFile(identityFile, []byte(identity+"\n"), 0o600)
		_ = os.WriteFile(authorized, []byte(func() string {
			if identity == lines[0] {
				return lines[0] + "\n"
			}
			return ""
		}()), 0o600)
		command := exec.Command("ssh", "-F", "/dev/null", "-p", fmt.Sprint(port), "-o", "BatchMode=yes",
			"-o", "StrictHostKeyChecking=accept-new", "-o", "UserKnownHostsFile="+knownHosts,
			"-o", "IdentitiesOnly=yes", "-o", "IdentityFile="+identityFile, "root@127.0.0.1", "echo", "connected")
		command.Env = environment
		output, err := command.CombinedOutput()
		if err != nil || !strings.Contains(string(output), "connected") {
			t.Fatalf("ssh with %s: %v\n%s\nsshd: %s", strings.Fields(identity)[0], err, output, serverLog.String())
		}
	}
	if fixture.operations()[events.OperationSSHSessionBind] == 0 {
		t.Fatal("no session-bind recorded")
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

func waitForPort(t *testing.T, port int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if connection, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port)); err == nil {
			_ = connection.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("sshd did not start")
}
