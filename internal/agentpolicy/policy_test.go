// ---
// relationships:
//   verifies: linux-per-user-agent-proxy
// ---

package agentpolicy_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/wyrd-company/wyrwood/internal/agentpolicy"
	"github.com/wyrd-company/wyrwood/internal/config"
	"github.com/wyrd-company/wyrwood/internal/runtime"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

const (
	testSocket             = "/run/consumer/agent.sock"
	sessionBindExtension   = "session-bind@openssh.com"
	openSSHAgentMaxMessage = 256 * 1024
)

func TestProtocolFiltersIdentitiesByFingerprintNotComment(t *testing.T) {
	t.Parallel()

	fixture := newFixture(t)
	client, closeClient := serveClient(t, fixture.policyAgent)
	defer closeClient()

	keys, err := client.List()
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("len(List()) = %d, want 1", len(keys))
	}
	if got := ssh.FingerprintSHA256(keys[0]); got != fixture.allowedFingerprint {
		t.Fatalf("listed fingerprint = %q, want %q", got, fixture.allowedFingerprint)
	}
	if keys[0].Comment != "shared display label" {
		t.Fatalf("listed comment = %q", keys[0].Comment)
	}
	if slices.ContainsFunc(keys, func(key *agent.Key) bool {
		return ssh.FingerprintSHA256(key) == fixture.deniedFingerprint
	}) {
		t.Fatal("List() exposed a denied key with the same comment")
	}
}

func TestProtocolSignsOnlyAllowedFingerprints(t *testing.T) {
	t.Parallel()

	fixture := newFixture(t)
	client, closeClient := serveClient(t, fixture.policyAgent)
	defer closeClient()
	payload := []byte("generic authentication challenge")

	signature, err := client.Sign(fixture.allowedKey, payload)
	if err != nil {
		t.Fatalf("Sign(allowed) error = %v", err)
	}
	if err := fixture.allowedKey.Verify(payload, signature); err != nil {
		t.Fatalf("allowed signature verification error = %v", err)
	}
	if _, err := client.Sign(fixture.deniedKey, payload); err == nil {
		t.Fatal("Sign(denied) error = nil")
	}
}

func TestProtocolPreservesSignatureFlags(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	publicKey, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("ssh.NewPublicKey() error = %v", err)
	}
	keyring := agent.NewKeyring()
	if err := keyring.Add(agent.AddedKey{PrivateKey: privateKey}); err != nil {
		t.Fatalf("Add(fixture key) error = %v", err)
	}
	upstream := &recordingAgent{ExtendedAgent: keyring.(agent.ExtendedAgent)}
	store, err := runtime.NewStore(testConfiguration([]string{ssh.FingerprintSHA256(publicKey)}))
	if err != nil {
		t.Fatalf("runtime.NewStore() error = %v", err)
	}
	policyAgent, err := agentpolicy.New(store, testSocket, upstream)
	if err != nil {
		t.Fatalf("agentpolicy.New() error = %v", err)
	}
	client, closeClient := serveClient(t, policyAgent)
	defer closeClient()

	signature, err := client.SignWithFlags(publicKey, []byte("generic authentication challenge"), agent.SignatureFlagRsaSha512)
	if err != nil {
		t.Fatalf("SignWithFlags(allowed) error = %v", err)
	}
	if signature.Format != ssh.KeyAlgoRSASHA512 {
		t.Fatalf("signature format = %q, want %q", signature.Format, ssh.KeyAlgoRSASHA512)
	}
	if got := upstream.lastSignatureFlags(); got != agent.SignatureFlagRsaSha512 {
		t.Fatalf("upstream signature flags = %d, want %d", got, agent.SignatureFlagRsaSha512)
	}
}

func TestProtocolReevaluatesPolicyOnExistingConnection(t *testing.T) {
	t.Parallel()

	fixture := newFixture(t)
	client, closeClient := serveClient(t, fixture.policyAgent)
	defer closeClient()
	payload := []byte("generic authentication challenge")

	if _, err := client.Sign(fixture.allowedKey, payload); err != nil {
		t.Fatalf("Sign(before removal) error = %v", err)
	}
	next := testConfiguration(nil)
	prepared, err := fixture.store.Prepare(next)
	if err != nil {
		t.Fatalf("Store.Prepare() error = %v", err)
	}
	if err := fixture.store.Commit(prepared); err != nil {
		t.Fatalf("Store.Commit() error = %v", err)
	}

	keys, err := client.List()
	if err != nil {
		t.Fatalf("List(after removal) error = %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("len(List(after removal)) = %d, want 0", len(keys))
	}
	if _, err := client.Sign(fixture.allowedKey, payload); err == nil {
		t.Fatal("Sign(after removal) error = nil")
	}
}

func TestProtocolForwardsOnlyWellFramedSessionBind(t *testing.T) {
	t.Parallel()

	fixture := newFixture(t)
	client, closeClient := serveClient(t, fixture.policyAgent)
	defer closeClient()
	contents := ssh.Marshal(struct {
		HostKey      []byte
		SessionID    []byte
		Signature    []byte
		IsForwarding bool
	}{
		HostKey:      []byte("opaque host key"),
		SessionID:    []byte("opaque session identifier"),
		Signature:    []byte("opaque host signature"),
		IsForwarding: true,
	})

	response, err := client.Extension(sessionBindExtension, contents)
	if err != nil {
		t.Fatalf("Extension(session-bind) error = %v", err)
	}
	if !bytes.Equal(response, []byte{6}) {
		t.Fatalf("Extension(session-bind) response = %v, want success", response)
	}
	if got := fixture.upstream.extensionContents(); !bytes.Equal(got, contents) {
		t.Fatalf("upstream extension contents changed: got %x, want %x", got, contents)
	}

	before := fixture.upstream.extensionCount()
	if _, err := client.Extension(sessionBindExtension, []byte("malformed")); err == nil {
		t.Fatal("Extension(malformed session-bind) error = nil")
	}
	if got := fixture.upstream.extensionCount(); got != before {
		t.Fatalf("malformed session-bind forwarded %d calls, want %d", got, before)
	}
	if _, err := client.Extension(sessionBindExtension, append(slices.Clone(contents), 0)); err == nil {
		t.Fatal("Extension(session-bind with trailing data) error = nil")
	}
	if got := fixture.upstream.extensionCount(); got != before {
		t.Fatalf("session-bind with trailing data forwarded %d calls, want %d", got, before)
	}
	if _, err := client.Extension("query@example.invalid", contents); !errors.Is(err, agent.ErrExtensionUnsupported) {
		t.Fatalf("Extension(unknown) error = %v, want ErrExtensionUnsupported", err)
	}
	if got := fixture.upstream.extensionCount(); got != before {
		t.Fatalf("unknown extension forwarded %d calls, want %d", got, before)
	}
	// The task contract intentionally permits session-bind only. RFC 9987's
	// query extension must not create a second allowlisted extension.
	if _, err := client.Extension("query", nil); !errors.Is(err, agent.ErrExtensionUnsupported) {
		t.Fatalf("Extension(query) error = %v, want ErrExtensionUnsupported", err)
	}
	if got := fixture.upstream.extensionCount(); got != before {
		t.Fatalf("query extension forwarded %d calls, want %d", got, before)
	}
}

func TestProtocolRejectsEmptySuccessfulExtensionResponse(t *testing.T) {
	t.Parallel()

	fixture := newFixture(t)
	fixture.upstream.setExtensionResponse(nil)
	client, closeClient := serveClient(t, fixture.policyAgent)
	defer closeClient()

	if _, err := client.Extension(sessionBindExtension, sessionBindContents()); err == nil {
		t.Fatal("Extension(empty upstream response) error = nil")
	} else if errors.Is(err, agent.ErrExtensionUnsupported) {
		t.Fatalf("Extension(empty upstream response) error = %v, want extension failure", err)
	}
}

func TestProtocolEnforcesOpenSSHAgentMessageLimit(t *testing.T) {
	t.Parallel()

	fixture := newFixture(t)
	exactRequest := make([]byte, openSSHAgentMaxMessage)
	exactRequest[0] = 255
	if reply := exchangeRaw(t, fixture.policyAgent, exactRequest); !bytes.Equal(reply, []byte{5}) {
		t.Fatalf("exact-limit request reply = %v, want failure", reply)
	}
	assertRequestRejectedBeforeBody(t, fixture.policyAgent, openSSHAgentMaxMessage+1)

	exactResponse := make([]byte, openSSHAgentMaxMessage)
	exactResponse[0] = 6
	fixture.upstream.setExtensionResponse(exactResponse)
	client, closeClient := serveClient(t, fixture.policyAgent)
	response, err := client.Extension(sessionBindExtension, sessionBindContents())
	closeClient()
	if err != nil {
		t.Fatalf("Extension(exact-limit response) error = %v", err)
	}
	if len(response) != openSSHAgentMaxMessage {
		t.Fatalf("exact-limit response length = %d, want %d", len(response), openSSHAgentMaxMessage)
	}

	fixture.upstream.setExtensionResponse(make([]byte, openSSHAgentMaxMessage+1))
	client, closeClient = serveClient(t, fixture.policyAgent)
	if _, err := client.Extension(sessionBindExtension, sessionBindContents()); !errors.Is(err, agent.ErrExtensionUnsupported) {
		t.Fatalf("Extension(over-limit response) error = %v, want ErrExtensionUnsupported", err)
	}
	closeClient()
}

func TestProtocolRejectsMutationsAndUnknownOpcodesBeforeDecoding(t *testing.T) {
	t.Parallel()

	fixture := newFixture(t)
	for _, opcode := range []byte{1, 9, 17, 18, 19, 20, 21, 22, 23, 25, 26, 255} {
		opcode := opcode
		t.Run(fmt.Sprintf("opcode-%d", opcode), func(t *testing.T) {
			reply := exchangeRaw(t, fixture.policyAgent, []byte{opcode})
			if !bytes.Equal(reply, []byte{5}) {
				t.Fatalf("opcode %d reply = %v, want failure", opcode, reply)
			}
		})
	}

	client, closeClient := serveClient(t, fixture.policyAgent)
	defer closeClient()
	_, privateKey := newKey(t)
	if err := client.Add(agent.AddedKey{PrivateKey: privateKey, Comment: "display label"}); err == nil {
		t.Fatal("Add() error = nil")
	}
	if err := client.Add(agent.AddedKey{PrivateKey: privateKey, LifetimeSecs: 1}); err == nil {
		t.Fatal("Add(constrained) error = nil")
	}
	if err := client.Remove(fixture.allowedKey); err == nil {
		t.Fatal("Remove() error = nil")
	}
	if err := client.RemoveAll(); err == nil {
		t.Fatal("RemoveAll() error = nil")
	}
	if err := client.Lock([]byte("generic passphrase")); err == nil {
		t.Fatal("Lock() error = nil")
	}
	if err := client.Unlock([]byte("generic passphrase")); err == nil {
		t.Fatal("Unlock() error = nil")
	}
	if got := fixture.upstream.mutationCount(); got != 0 {
		t.Fatalf("upstream mutation count = %d, want 0", got)
	}
}

func TestConcurrentPolicyReplacementAndRequests(t *testing.T) {
	fixture := newFixture(t)
	client, closeClient := serveClient(t, fixture.policyAgent)
	defer closeClient()

	const replacements = 200
	done := make(chan struct{})
	requestErrors := make(chan error, 1)
	go func() {
		defer close(done)
		for range replacements {
			keys, err := client.List()
			if err != nil {
				requestErrors <- err
				return
			}
			if len(keys) > 1 {
				requestErrors <- errors.New("identity response combined policy snapshots")
				return
			}
		}
	}()

	for index := range replacements {
		fingerprints := []string(nil)
		if index%2 == 0 {
			fingerprints = []string{fixture.allowedFingerprint}
		}
		prepared, err := fixture.store.Prepare(testConfiguration(fingerprints))
		if err != nil {
			t.Fatalf("Store.Prepare() error = %v", err)
		}
		if err := fixture.store.Commit(prepared); err != nil {
			t.Fatalf("Store.Commit() error = %v", err)
		}
	}
	<-done
	select {
	case err := <-requestErrors:
		t.Fatalf("concurrent request error = %v", err)
	default:
	}
}

type fixture struct {
	store              *runtime.Store
	policyAgent        *agentpolicy.Agent
	upstream           *recordingAgent
	allowedKey         ssh.PublicKey
	deniedKey          ssh.PublicKey
	allowedFingerprint string
	deniedFingerprint  string
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	allowedKey, allowedPrivate := newKey(t)
	deniedKey, deniedPrivate := newKey(t)
	keyring := agent.NewKeyring()
	if err := keyring.Add(agent.AddedKey{PrivateKey: allowedPrivate, Comment: "shared display label"}); err != nil {
		t.Fatalf("Add(allowed fixture key) error = %v", err)
	}
	if err := keyring.Add(agent.AddedKey{PrivateKey: deniedPrivate, Comment: "shared display label"}); err != nil {
		t.Fatalf("Add(denied fixture key) error = %v", err)
	}
	upstream := &recordingAgent{
		ExtendedAgent:  keyring.(agent.ExtendedAgent),
		extensionReply: []byte{6},
	}
	allowedFingerprint := ssh.FingerprintSHA256(allowedKey)
	store, err := runtime.NewStore(testConfiguration([]string{allowedFingerprint}))
	if err != nil {
		t.Fatalf("runtime.NewStore() error = %v", err)
	}
	policyAgent, err := agentpolicy.New(store, testSocket, upstream)
	if err != nil {
		t.Fatalf("agentpolicy.New() error = %v", err)
	}
	return fixture{
		store:              store,
		policyAgent:        policyAgent,
		upstream:           upstream,
		allowedKey:         allowedKey,
		deniedKey:          deniedKey,
		allowedFingerprint: allowedFingerprint,
		deniedFingerprint:  ssh.FingerprintSHA256(deniedKey),
	}
}

func newKey(t *testing.T) (ssh.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() error = %v", err)
	}
	key, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatalf("ssh.NewPublicKey() error = %v", err)
	}
	return key, private
}

func testConfiguration(fingerprints []string) config.Config {
	return config.Config{
		Upstream: "/run/upstream/agent.sock",
		Consumers: []config.Consumer{{
			Name:         "consumer",
			Socket:       testSocket,
			Fingerprints: slices.Clone(fingerprints),
		}},
		Timeouts: config.DefaultTimeouts(),
	}
}

func sessionBindContents() []byte {
	return ssh.Marshal(struct {
		HostKey      []byte
		SessionID    []byte
		Signature    []byte
		IsForwarding bool
	}{
		HostKey:      []byte("opaque host key"),
		SessionID:    []byte("opaque session identifier"),
		Signature:    []byte("opaque host signature"),
		IsForwarding: true,
	})
}

func serveClient(t *testing.T, policyAgent *agentpolicy.Agent) (agent.ExtendedAgent, func()) {
	t.Helper()
	clientConnection, serverConnection := net.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- agentpolicy.Serve(policyAgent, serverConnection)
	}()
	closeClient := func() {
		_ = clientConnection.Close()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				t.Errorf("Serve() error = %v", err)
			}
		case <-time.After(time.Second):
			t.Error("Serve() did not stop")
		}
	}
	return agent.NewClient(clientConnection), closeClient
}

func exchangeRaw(t *testing.T, policyAgent *agentpolicy.Agent, request []byte) []byte {
	t.Helper()
	clientConnection, serverConnection := net.Pipe()
	if err := clientConnection.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set connection deadline error = %v", err)
	}
	done := make(chan error, 1)
	go func() {
		done <- agentpolicy.Serve(policyAgent, serverConnection)
	}()

	frame := make([]byte, 4+len(request))
	binary.BigEndian.PutUint32(frame, uint32(len(request)))
	copy(frame[4:], request)
	if _, err := clientConnection.Write(frame); err != nil {
		t.Fatalf("write request error = %v", err)
	}
	var length [4]byte
	if _, err := io.ReadFull(clientConnection, length[:]); err != nil {
		t.Fatalf("read response length error = %v", err)
	}
	reply := make([]byte, binary.BigEndian.Uint32(length[:]))
	if _, err := io.ReadFull(clientConnection, reply); err != nil {
		t.Fatalf("read response error = %v", err)
	}
	_ = clientConnection.Close()
	<-done
	return reply
}

func assertRequestRejectedBeforeBody(t *testing.T, policyAgent *agentpolicy.Agent, size uint32) {
	t.Helper()
	var connection bytes.Buffer
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], size)
	if _, err := connection.Write(length[:]); err != nil {
		t.Fatalf("write request length error = %v", err)
	}
	if err := agentpolicy.Serve(policyAgent, &connection); err == nil || err.Error() != "agent request exceeds size limit" {
		t.Fatalf("Serve(over-limit request) error = %v, want size-limit error", err)
	}
}

type recordingAgent struct {
	agent.ExtendedAgent
	mu             sync.Mutex
	extensions     [][]byte
	extensionReply []byte
	mutations      int
	signatureFlags agent.SignatureFlags
}

func (recorder *recordingAgent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	recorder.mu.Lock()
	recorder.signatureFlags = flags
	recorder.mu.Unlock()
	return recorder.ExtendedAgent.SignWithFlags(key, data, flags)
}

func (recorder *recordingAgent) Extension(extensionType string, contents []byte) ([]byte, error) {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if extensionType != sessionBindExtension {
		return nil, agent.ErrExtensionUnsupported
	}
	recorder.extensions = append(recorder.extensions, slices.Clone(contents))
	return slices.Clone(recorder.extensionReply), nil
}

func (recorder *recordingAgent) Add(key agent.AddedKey) error {
	recorder.recordMutation()
	return errors.New("unexpected add")
}

func (recorder *recordingAgent) Remove(key ssh.PublicKey) error {
	recorder.recordMutation()
	return errors.New("unexpected remove")
}

func (recorder *recordingAgent) RemoveAll() error {
	recorder.recordMutation()
	return errors.New("unexpected remove all")
}

func (recorder *recordingAgent) Lock(passphrase []byte) error {
	recorder.recordMutation()
	return errors.New("unexpected lock")
}

func (recorder *recordingAgent) Unlock(passphrase []byte) error {
	recorder.recordMutation()
	return errors.New("unexpected unlock")
}

func (recorder *recordingAgent) recordMutation() {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	recorder.mutations++
}

func (recorder *recordingAgent) mutationCount() int {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	return recorder.mutations
}

func (recorder *recordingAgent) extensionCount() int {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	return len(recorder.extensions)
}

func (recorder *recordingAgent) extensionContents() []byte {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if len(recorder.extensions) == 0 {
		return nil
	}
	return slices.Clone(recorder.extensions[len(recorder.extensions)-1])
}

func (recorder *recordingAgent) lastSignatureFlags() agent.SignatureFlags {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	return recorder.signatureFlags
}

func (recorder *recordingAgent) setExtensionResponse(response []byte) {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	recorder.extensionReply = slices.Clone(response)
}
