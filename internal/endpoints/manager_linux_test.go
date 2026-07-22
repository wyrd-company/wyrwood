//go:build linux

// ---
// relationships:
//   verifies: linux-per-user-agent-proxy
// ---

package endpoints

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/wyrd-company/wyrwood/internal/config"
	"github.com/wyrd-company/wyrwood/internal/events"
	"github.com/wyrd-company/wyrwood/internal/runtime"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/sys/unix"
)

func TestApplyDoesNotAcceptBeforeCommitAndPublishesFilteredEndpoint(t *testing.T) {
	root := t.TempDir()
	upstreamPath := filepath.Join(root, "service", "agent.sock")
	allowedKey, allowedPrivate := generateKey(t)
	hiddenKey, hiddenPrivate := generateKey(t)
	upstream := startAgentServer(t, upstreamPath, allowedPrivate, hiddenPrivate)
	defer upstream.close(t)

	sink := &recordingSink{}
	manager := openEmptyManager(t, root, upstreamPath, sink)
	defer closeManager(t, manager)

	staged := make(chan struct{})
	commit := make(chan struct{})
	manager.applyMu.Lock()
	manager.deps.beforeCommit = func() {
		close(staged)
		<-commit
	}
	manager.applyMu.Unlock()
	consumerPath := filepath.Join(root, "subject", "agent.sock")
	next := configuration(upstreamPath, consumer("sample", consumerPath, nil, ssh.FingerprintSHA256(allowedKey)))
	applyDone := make(chan error, 1)
	go func() {
		_, err := manager.Apply(next)
		applyDone <- err
	}()
	select {
	case <-staged:
	case <-time.After(time.Second):
		t.Fatal("listener was not staged")
	}

	connection, err := net.DialTimeout("unix", consumerPath, time.Second)
	if err != nil {
		t.Fatalf("dial staged listener: %v", err)
	}
	defer connection.Close()
	client := agent.NewClient(connection)
	listed := make(chan []*agent.Key, 1)
	listErrors := make(chan error, 1)
	go func() {
		keys, listErr := client.List()
		listed <- keys
		listErrors <- listErr
	}()
	select {
	case err := <-listErrors:
		t.Fatalf("staged listener served before commit: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	close(commit)
	if err := <-applyDone; err != nil {
		t.Fatalf("Apply(): %v", err)
	}
	if err := <-listErrors; err != nil {
		t.Fatalf("List(): %v", err)
	}
	keys := <-listed
	if len(keys) != 1 || ssh.FingerprintSHA256(keys[0]) != ssh.FingerprintSHA256(allowedKey) {
		t.Fatalf("filtered identities = %v", fingerprints(keys))
	}
	if slices.Contains(fingerprints(keys), ssh.FingerprintSHA256(hiddenKey)) {
		t.Fatal("hidden identity crossed the consumer policy")
	}
	assertMode(t, filepath.Dir(consumerPath), 0o700)
	assertMode(t, consumerPath, 0o600)
	if !sink.contains(events.OperationConsumerConnect, events.OutcomeSucceeded) {
		t.Fatal("consumer connection event was not recorded")
	}
}

func TestPolicyUpdateAffectsAnOpenConnectionAndRetirementClosesIt(t *testing.T) {
	root := t.TempDir()
	upstreamPath := filepath.Join(root, "service", "agent.sock")
	firstKey, firstPrivate := generateKey(t)
	secondKey, secondPrivate := generateKey(t)
	upstream := startAgentServer(t, upstreamPath, firstPrivate, secondPrivate)
	defer upstream.close(t)

	consumerPath := filepath.Join(root, "subject", "agent.sock")
	initial := configuration(upstreamPath, consumer("sample", consumerPath, nil, ssh.FingerprintSHA256(firstKey)))
	manager, err := Open(initial, &recordingSink{})
	if err != nil {
		t.Fatalf("Open(): %v", err)
	}
	defer closeManager(t, manager)
	connection, err := net.Dial("unix", consumerPath)
	if err != nil {
		t.Fatal(err)
	}
	client := agent.NewClient(connection)
	assertListedFingerprints(t, client, []string{ssh.FingerprintSHA256(firstKey)})

	next := configuration(upstreamPath, consumer("renamed", consumerPath, nil, ssh.FingerprintSHA256(secondKey)))
	result, err := manager.Apply(next)
	if err != nil {
		t.Fatalf("Apply(update): %v", err)
	}
	if !result.Committed || result.Degraded {
		t.Fatalf("Apply(update) = %#v", result)
	}
	assertListedFingerprints(t, client, []string{ssh.FingerprintSHA256(secondKey)})

	parent := filepath.Dir(consumerPath)
	result, err = manager.Apply(configuration(upstreamPath))
	if err != nil {
		t.Fatalf("Apply(retire): %v", err)
	}
	if !result.Committed || result.Degraded {
		t.Fatalf("Apply(retire) = %#v", result)
	}
	if _, err := os.Lstat(consumerPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("retired socket still exists: %v", err)
	}
	if info, err := os.Stat(parent); err != nil || !info.IsDir() {
		t.Fatalf("consumer parent was removed: %v", err)
	}
	if _, err := client.List(); err == nil {
		t.Fatal("retired active connection remained usable")
	}
	_ = connection.Close()
}

func TestAccessGroupChangeRevokesBeforeCommitAndClosesExistingConnection(t *testing.T) {
	root := t.TempDir()
	upstreamPath := filepath.Join(root, "service", "agent.sock")
	publicKey, privateKey := generateKey(t)
	upstream := startAgentServer(t, upstreamPath, privateKey)
	defer upstream.close(t)
	path := filepath.Join(root, "subject", "agent.sock")
	manager, err := Open(configuration(upstreamPath, consumer("sample", path, nil, ssh.FingerprintSHA256(publicKey))), &recordingSink{})
	if err != nil {
		t.Fatal(err)
	}
	defer closeManager(t, manager)
	connection, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	client := agent.NewClient(connection)
	assertListedFingerprints(t, client, []string{ssh.FingerprintSHA256(publicKey)})

	prepared := make(chan struct{})
	commit := make(chan struct{})
	manager.applyMu.Lock()
	manager.deps.beforeCommit = func() {
		close(prepared)
		<-commit
	}
	manager.applyMu.Unlock()
	group := uint32(os.Getegid())
	applyDone := make(chan error, 1)
	go func() {
		_, applyErr := manager.Apply(configuration(upstreamPath, consumer("sample", path, &group, ssh.FingerprintSHA256(publicKey))))
		applyDone <- applyErr
	}()
	select {
	case <-prepared:
	case <-time.After(time.Second):
		t.Fatal("group transition did not reach commit boundary")
	}
	assertMode(t, filepath.Dir(path), 0o700)
	assertMode(t, path, 0o600)
	assertListedFingerprints(t, client, []string{ssh.FingerprintSHA256(publicKey)})
	close(commit)
	if err := <-applyDone; err != nil {
		t.Fatalf("Apply(group change): %v", err)
	}
	assertMode(t, filepath.Dir(path), 0o710)
	assertMode(t, path, 0o660)
	if _, err := client.List(); err == nil {
		t.Fatal("connection admitted under the old access group remained usable")
	}
	upstreamDeadline := time.Now().Add(time.Second)
	for upstream.clientCount() != 0 && time.Now().Before(upstreamDeadline) {
		time.Sleep(time.Millisecond)
	}
	if count := upstream.clientCount(); count != 0 {
		t.Fatalf("paired upstream connections = %d, want 0", count)
	}
	_ = connection.Close()
}

func TestPostCommitGroupGrantFailureStaysOwnerOnlyUntilRetry(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "subject", "agent.sock")
	manager, err := Open(configuration(filepath.Join(root, "service", "agent.sock"), consumer("sample", path, nil, testFingerprint(1))), &recordingSink{})
	if err != nil {
		t.Fatal(err)
	}
	defer closeManager(t, manager)
	originalApply := manager.deps.applyPermissions
	fail := true
	manager.applyMu.Lock()
	manager.deps.applyPermissions = func(change *metadataChange) error {
		if change.postCommit && fail {
			return errors.New("injected candidate permission failure")
		}
		return originalApply(change)
	}
	manager.applyMu.Unlock()
	group := uint32(os.Getegid())
	result, err := manager.Apply(configuration(filepath.Join(root, "service", "agent.sock"), consumer("sample", path, &group, testFingerprint(2))))
	if err != nil || !result.Committed || !result.Degraded || result.PendingPermissions != 1 {
		t.Fatalf("Apply() = %#v, %v", result, err)
	}
	if policy, exists := manager.Policy(path); !exists || !policy.Allows(testFingerprint(2)) || policy.Allows(testFingerprint(1)) {
		t.Fatal("candidate policy did not remain committed")
	}
	assertMode(t, filepath.Dir(path), 0o700)
	assertMode(t, path, 0o600)
	blocked, blockedErr := manager.Apply(configuration(filepath.Join(root, "service", "agent.sock"), consumer("sample", path, nil, testFingerprint(3))))
	if blockedErr == nil || blocked.Committed {
		t.Fatalf("Apply(while permissions pending) = %#v, %v", blocked, blockedErr)
	}
	manager.applyMu.Lock()
	fail = false
	manager.applyMu.Unlock()
	if health := manager.RetryCleanup(); health.Degraded || health.PendingPermissions != 0 {
		t.Fatalf("RetryCleanup() = %#v", health)
	}
	assertMode(t, filepath.Dir(path), 0o710)
	assertMode(t, path, 0o660)
}

func TestPreparationFailureRollsBackStagedListenerAndActiveMetadata(t *testing.T) {
	root := t.TempDir()
	upstreamPath := filepath.Join(root, "service", "agent.sock")
	activePath := filepath.Join(root, "active", "agent.sock")
	sink := &recordingSink{}
	manager, err := Open(
		configuration(upstreamPath, consumer("active", activePath, nil, testFingerprint(1))),
		sink,
	)
	if err != nil {
		t.Fatalf("Open(): %v", err)
	}
	defer closeManager(t, manager)

	originalPrepare := manager.deps.prepareSocket
	preparedCount := 0
	stagedFD := -1
	manager.applyMu.Lock()
	manager.deps.prepareSocket = func(candidate runtime.Consumer) (*stagedSocket, error) {
		preparedCount++
		if preparedCount == 2 {
			return nil, errors.New("injected bind failure")
		}
		staged, prepareErr := originalPrepare(candidate)
		if staged != nil {
			stagedFD = staged.file.parent.fd
		}
		return staged, prepareErr
	}
	manager.applyMu.Unlock()
	group := uint32(os.Getegid())
	firstAdded := filepath.Join(root, "added-a", "agent.sock")
	secondAdded := filepath.Join(root, "added-b", "agent.sock")
	next := configuration(upstreamPath,
		consumer("active", activePath, &group, testFingerprint(2)),
		consumer("added-a", firstAdded, nil, testFingerprint(3)),
		consumer("added-b", secondAdded, nil, testFingerprint(4)),
	)
	result, err := manager.Apply(next)
	if err == nil || result.Committed {
		t.Fatalf("Apply() = %#v, %v", result, err)
	}
	if policy, exists := manager.Policy(activePath); !exists || !policy.Allows(testFingerprint(1)) || policy.Allows(testFingerprint(2)) {
		t.Fatal("active policy changed after preparation failure")
	}
	assertMode(t, filepath.Dir(activePath), 0o700)
	assertMode(t, activePath, 0o600)
	if _, err := os.Lstat(firstAdded); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("staged socket survived rollback: %v", err)
	}
	if info, err := os.Stat(filepath.Dir(firstAdded)); err != nil || !info.IsDir() {
		t.Fatalf("staged parent did not remain: %v", err)
	}
	if _, err := os.Stat(filepath.Dir(secondAdded)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failing candidate unexpectedly created a parent: %v", err)
	}
	if !sink.contains(events.OperationReconcile, events.OutcomeFailed) {
		t.Fatal("preparation failure was not recorded categorically")
	}
	assertFDClosed(t, stagedFD)
}

func TestFailedOpenClosesPinnedFDWhenRollbackCleanupCannotFinish(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "subject", "agent.sock")
	deps := defaultDependencies()
	originalPrepare := deps.prepareSocket
	pinnedFD := -1
	deps.prepareSocket = func(candidate runtime.Consumer) (*stagedSocket, error) {
		staged, err := originalPrepare(candidate)
		if err != nil {
			return staged, err
		}
		pinnedFD = staged.file.parent.fd
		return staged, errors.New("injected preparation failure after bind")
	}
	deps.removeSocket = func(*endpointFile) error {
		return errors.New("injected persistent rollback cleanup failure")
	}

	manager, err := openWithDependencies(
		configuration(filepath.Join(root, "service", "agent.sock"), consumer("sample", path, nil, testFingerprint(1))),
		&recordingSink{},
		deps,
	)
	if err == nil || manager != nil {
		t.Fatalf("openWithDependencies() = %#v, %v", manager, err)
	}
	if pinnedFD < 0 {
		t.Fatal("preparation did not expose a pinned parent descriptor")
	}
	assertFDClosed(t, pinnedFD)
}

func TestPostCommitCleanupFailureIsDegradedAndRetryable(t *testing.T) {
	root := t.TempDir()
	upstreamPath := filepath.Join(root, "service", "agent.sock")
	consumerPath := filepath.Join(root, "subject", "agent.sock")
	manager, err := Open(
		configuration(upstreamPath, consumer("sample", consumerPath, nil, testFingerprint(1))),
		&recordingSink{},
	)
	if err != nil {
		t.Fatalf("Open(): %v", err)
	}
	defer closeManager(t, manager)

	originalRemove := manager.deps.removeSocket
	fail := true
	manager.applyMu.Lock()
	manager.deps.removeSocket = func(file *endpointFile) error {
		if fail {
			return errors.New("injected cleanup failure")
		}
		return originalRemove(file)
	}
	manager.applyMu.Unlock()
	result, err := manager.Apply(configuration(upstreamPath))
	if err != nil {
		t.Fatalf("Apply(): %v", err)
	}
	if !result.Committed || !result.Degraded || result.PendingCleanup != 1 {
		t.Fatalf("Apply() = %#v", result)
	}
	if _, exists := manager.Policy(consumerPath); exists {
		t.Fatal("retired policy was restored after cleanup failure")
	}
	if _, err := os.Lstat(consumerPath); err != nil {
		t.Fatalf("failed-cleanup socket absent: %v", err)
	}
	if _, err := os.Stat(filepath.Dir(consumerPath)); err != nil {
		t.Fatalf("consumer parent absent: %v", err)
	}

	manager.applyMu.Lock()
	fail = false
	manager.applyMu.Unlock()
	health := manager.RetryCleanup()
	if health.Degraded || health.PendingCleanup != 0 {
		t.Fatalf("RetryCleanup() = %#v", health)
	}
	if _, err := os.Lstat(consumerPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("retried cleanup left socket: %v", err)
	}
}

func TestListenerSurvivesUpstreamOutageAndRecoversOnTheSameConnection(t *testing.T) {
	root := t.TempDir()
	upstreamPath := filepath.Join(root, "service", "agent.sock")
	consumerPath := filepath.Join(root, "subject", "agent.sock")
	publicKey, privateKey := generateKey(t)
	manager, err := Open(
		configuration(upstreamPath, consumer("sample", consumerPath, nil, ssh.FingerprintSHA256(publicKey))),
		&recordingSink{},
	)
	if err != nil {
		t.Fatalf("Open(): %v", err)
	}
	defer closeManager(t, manager)

	connection, err := net.Dial("unix", consumerPath)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	client := agent.NewClient(connection)
	if _, err := client.List(); err == nil {
		t.Fatal("List() succeeded while upstream was absent")
	}
	upstream := startAgentServer(t, upstreamPath, privateKey)
	defer upstream.close(t)
	assertListedFingerprints(t, client, []string{ssh.FingerprintSHA256(publicKey)})
}

func TestConfiguredGroupModesAreAppliedExactly(t *testing.T) {
	root := t.TempDir()
	group := uint32(os.Getegid())
	consumerPath := filepath.Join(root, "subject", "agent.sock")
	manager, err := Open(
		configuration(filepath.Join(root, "service", "agent.sock"), consumer("sample", consumerPath, &group, testFingerprint(1))),
		&recordingSink{},
	)
	if err != nil {
		t.Fatalf("Open(): %v", err)
	}
	defer closeManager(t, manager)
	assertMode(t, filepath.Dir(consumerPath), 0o710)
	assertMode(t, consumerPath, 0o660)
	for _, path := range []string{filepath.Dir(consumerPath), consumerPath} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if stat, ok := info.Sys().(*syscall.Stat_t); ok && stat.Gid != group {
			t.Errorf("%s group = %d, want %d", filepath.Base(path), stat.Gid, group)
		}
	}
}

func TestPreparationRejectsAGroupTheDaemonDoesNotBelongTo(t *testing.T) {
	root := t.TempDir()
	manager := openEmptyManager(t, root, filepath.Join(root, "service", "agent.sock"), &recordingSink{})
	defer closeManager(t, manager)
	group := uint32(4_294_967_294)
	path := filepath.Join(root, "subject", "agent.sock")
	result, err := manager.Apply(configuration(
		filepath.Join(root, "service", "agent.sock"),
		consumer("sample", path, &group, testFingerprint(1)),
	))
	if err == nil || result.Committed {
		t.Fatalf("Apply() = %#v, %v", result, err)
	}
	if _, err := os.Stat(filepath.Dir(path)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("invalid group changed filesystem: %v", err)
	}
}

func TestPreparationRejectsNonSocketAndSymlinkEntries(t *testing.T) {
	root := t.TempDir()
	upstreamPath := filepath.Join(root, "service", "agent.sock")
	manager := openEmptyManager(t, root, upstreamPath, &recordingSink{})
	defer closeManager(t, manager)

	regularParent := filepath.Join(root, "regular")
	if err := os.Mkdir(regularParent, 0o700); err != nil {
		t.Fatal(err)
	}
	regularPath := filepath.Join(regularParent, "agent.sock")
	if err := os.WriteFile(regularPath, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	if result, err := manager.Apply(configuration(upstreamPath, consumer("sample", regularPath, nil, testFingerprint(1)))); err == nil || result.Committed {
		t.Fatalf("Apply(non-socket) = %#v, %v", result, err)
	}
	contents, err := os.ReadFile(regularPath)
	if err != nil || string(contents) != "fixture" {
		t.Fatalf("non-socket entry was changed: %q, %v", contents, err)
	}

	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	symlinkParent := filepath.Join(root, "linked")
	if err := os.Symlink(target, symlinkParent); err != nil {
		t.Fatal(err)
	}
	symlinkPath := filepath.Join(symlinkParent, "agent.sock")
	if result, err := manager.Apply(configuration(upstreamPath, consumer("sample", symlinkPath, nil, testFingerprint(1)))); err == nil || result.Committed {
		t.Fatalf("Apply(symlink parent) = %#v, %v", result, err)
	}
	if entries, err := os.ReadDir(target); err != nil || len(entries) != 0 {
		t.Fatalf("symlink target was changed: %v, %v", entries, err)
	}
}

func TestCleanupDoesNotRemoveAReplacementEntry(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "subject", "agent.sock")
	manager, err := Open(
		configuration(filepath.Join(root, "service", "agent.sock"), consumer("sample", path, nil, testFingerprint(1))),
		&recordingSink{},
	)
	if err != nil {
		t.Fatal(err)
	}
	pinnedFD := manager.active[path].file.parent.fd
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := manager.Close(); err != nil {
		t.Fatalf("Close(): %v", err)
	}
	assertFDClosed(t, pinnedFD)
	contents, err := os.ReadFile(path)
	if err != nil || string(contents) != "replacement" {
		t.Fatalf("replacement entry changed: %q, %v", contents, err)
	}
}

func TestRetirementCleansSocketThroughRenamedPinnedParent(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, "subject")
	path := filepath.Join(parent, "agent.sock")
	upstream := filepath.Join(root, "service", "agent.sock")
	manager, err := Open(configuration(upstream, consumer("sample", path, nil, testFingerprint(1))), &recordingSink{})
	if err != nil {
		t.Fatal(err)
	}
	pinnedFD := manager.active[path].file.parent.fd
	renamed := filepath.Join(root, "renamed")
	if err := os.Rename(parent, renamed); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(parent, "marker.txt")
	if err := os.WriteFile(marker, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := manager.Apply(configuration(upstream))
	if err != nil || result.Degraded {
		t.Fatalf("Apply(retire): %#v, %v", result, err)
	}
	if _, err := os.Lstat(filepath.Join(renamed, "agent.sock")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket remained in renamed mounted directory: %v", err)
	}
	if contents, err := os.ReadFile(marker); err != nil || string(contents) != "replacement" {
		t.Fatalf("replacement directory changed: %q, %v", contents, err)
	}
	assertFDClosed(t, pinnedFD)
	closeManager(t, manager)
}

func TestRenamedParentCleanupFailureRetainsPinnedFDUntilRetry(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, "subject")
	path := filepath.Join(parent, "agent.sock")
	upstream := filepath.Join(root, "service", "agent.sock")
	manager, err := Open(configuration(upstream, consumer("sample", path, nil, testFingerprint(1))), &recordingSink{})
	if err != nil {
		t.Fatal(err)
	}
	defer closeManager(t, manager)
	pinnedFD := manager.active[path].file.parent.fd
	renamed := filepath.Join(root, "renamed")
	if err := os.Rename(parent, renamed); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(parent, "marker.txt")
	if err := os.WriteFile(marker, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	originalRemove := manager.deps.removeSocket
	fail := true
	manager.applyMu.Lock()
	manager.deps.removeSocket = func(file *endpointFile) error {
		if fail {
			return errors.New("injected pinned cleanup failure")
		}
		return originalRemove(file)
	}
	manager.applyMu.Unlock()
	result, err := manager.Apply(configuration(upstream))
	if err != nil || !result.Degraded || result.PendingCleanup != 1 {
		t.Fatalf("Apply(retire): %#v, %v", result, err)
	}
	assertFDOpen(t, pinnedFD)
	if _, err := os.Lstat(filepath.Join(renamed, "agent.sock")); err != nil {
		t.Fatalf("pending socket absent before retry: %v", err)
	}
	manager.applyMu.Lock()
	fail = false
	manager.applyMu.Unlock()
	if health := manager.RetryCleanup(); health.Degraded || health.PendingCleanup != 0 {
		t.Fatalf("RetryCleanup() = %#v", health)
	}
	if _, err := os.Lstat(filepath.Join(renamed, "agent.sock")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("retry left socket in renamed directory: %v", err)
	}
	if contents, err := os.ReadFile(marker); err != nil || string(contents) != "replacement" {
		t.Fatalf("replacement directory changed: %q, %v", contents, err)
	}
	assertFDClosed(t, pinnedFD)
}

func TestTemporaryAcceptFailureRetriesAndRecoversHealth(t *testing.T) {
	root := t.TempDir()
	upstreamPath := filepath.Join(root, "service", "agent.sock")
	publicKey, privateKey := generateKey(t)
	upstream := startAgentServer(t, upstreamPath, privateKey)
	defer upstream.close(t)
	path := filepath.Join(root, "subject", "agent.sock")
	deps := defaultDependencies()
	originalAccept := deps.accept
	injected := make(chan struct{})
	var attempts atomic.Int32
	deps.accept = func(listener *net.UnixListener) (*net.UnixConn, error) {
		if attempts.Add(1) == 1 {
			close(injected)
			return nil, temporaryFixtureError{}
		}
		return originalAccept(listener)
	}
	manager, err := openWithDependencies(configuration(upstreamPath, consumer("sample", path, nil, ssh.FingerprintSHA256(publicKey))), &recordingSink{}, deps)
	if err != nil {
		t.Fatal(err)
	}
	defer closeManager(t, manager)
	select {
	case <-injected:
	case <-time.After(time.Second):
		t.Fatal("temporary accept failure was not injected")
	}
	degradedDeadline := time.Now().Add(time.Second)
	for !manager.Health().Degraded && time.Now().Before(degradedDeadline) {
		time.Sleep(time.Millisecond)
	}
	if !manager.Health().Degraded {
		t.Fatal("temporary accept failure did not report degraded health")
	}
	connection, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	assertListedFingerprints(t, agent.NewClient(connection), []string{ssh.FingerprintSHA256(publicKey)})
	deadline := time.Now().Add(time.Second)
	for manager.Health().Degraded && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if health := manager.Health(); health.Degraded || health.ListenerError {
		t.Fatalf("listener health did not recover: %#v", health)
	}
	if attempts.Load() < 2 {
		t.Fatalf("accept attempts = %d, want at least 2", attempts.Load())
	}
}

func TestCleanupFailureIsRetriedInTheBackground(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "subject", "agent.sock")
	deps := defaultDependencies()
	deps.retryInterval = 5 * time.Millisecond
	originalRemove := deps.removeSocket
	var attempts atomic.Int32
	deps.removeSocket = func(file *endpointFile) error {
		if attempts.Add(1) == 1 {
			return errors.New("injected first cleanup failure")
		}
		return originalRemove(file)
	}
	manager, err := openWithDependencies(
		configuration(filepath.Join(root, "service", "agent.sock"), consumer("sample", path, nil, testFingerprint(1))),
		&recordingSink{},
		deps,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer closeManager(t, manager)
	result, err := manager.Apply(configuration(filepath.Join(root, "service", "agent.sock")))
	if err != nil || !result.Degraded {
		t.Fatalf("Apply() = %#v, %v", result, err)
	}
	deadline := time.Now().Add(time.Second)
	for manager.Health().Degraded && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if health := manager.Health(); health.Degraded || health.PendingCleanup != 0 {
		t.Fatalf("background cleanup health = %#v", health)
	}
	if attempts.Load() < 2 {
		t.Fatalf("cleanup attempts = %d, want at least 2", attempts.Load())
	}
}

func TestPreparationDistinguishesLiveAndStaleOwnedSockets(t *testing.T) {
	root := t.TempDir()
	upstreamPath := filepath.Join(root, "service", "agent.sock")
	path := filepath.Join(root, "subject", "agent.sock")
	first, err := Open(
		configuration(upstreamPath, consumer("sample", path, nil, testFingerprint(1))),
		&recordingSink{},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer closeManager(t, first)
	second := openEmptyManager(t, root, upstreamPath, &recordingSink{})
	if result, err := second.Apply(configuration(upstreamPath, consumer("sample", path, nil, testFingerprint(1)))); err == nil || result.Committed {
		t.Fatalf("Apply(live socket) = %#v, %v", result, err)
	}
	closeManager(t, second)
	connection, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("live listener was disturbed: %v", err)
	}
	_ = connection.Close()
	closeManager(t, first)

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	stale, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	stale.SetUnlinkOnClose(false)
	if err := stale.Close(); err != nil {
		t.Fatal(err)
	}
	third, err := Open(
		configuration(upstreamPath, consumer("sample", path, nil, testFingerprint(1))),
		&recordingSink{},
	)
	if err != nil {
		t.Fatalf("Open(stale socket): %v", err)
	}
	closeManager(t, third)
}

func TestPreparationRejectsLinuxPathnameOverflowBeforeFilesystemChanges(t *testing.T) {
	root := t.TempDir()
	manager := openEmptyManager(t, root, filepath.Join(root, "service", "agent.sock"), &recordingSink{})
	defer closeManager(t, manager)
	leaf := strings.Repeat("x", maximumUnixSocketPathBytes)
	path := filepath.Join(root, leaf, "agent.sock")
	if len(path) <= maximumUnixSocketPathBytes {
		t.Fatal("fixture path does not exceed Linux pathname limit")
	}
	result, err := manager.Apply(configuration(
		filepath.Join(root, "service", "agent.sock"),
		consumer("sample", path, nil, testFingerprint(1)),
	))
	if err == nil || result.Committed {
		t.Fatalf("Apply() = %#v, %v", result, err)
	}
	if _, err := os.Stat(filepath.Dir(path)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("overflow path changed filesystem: %v", err)
	}
}

func TestEndpointLifecycleUsesTheDurableOperationalEventSink(t *testing.T) {
	root := t.TempDir()
	store, err := events.Open(filepath.Join(root, "history", "events.bin"), 16)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Errorf("event store Close(): %v", err)
		}
	}()
	path := filepath.Join(root, "subject", "agent.sock")
	manager, err := Open(
		configuration(filepath.Join(root, "service", "agent.sock"), consumer("sample", path, nil, testFingerprint(1))),
		store,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer closeManager(t, manager)
	connection, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	_ = connection.Close()
	deadline := time.Now().Add(time.Second)
	for len(store.Recent(16)) < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	recent := store.Recent(16)
	if len(recent) < 2 || recent[0].Operation != events.OperationReconcile || recent[1].Operation != events.OperationConsumerConnect {
		t.Fatalf("durable endpoint events = %#v", recent)
	}
	if recent[0].ConsumerID != recent[1].ConsumerID || strings.Contains(string(recent[0].ConsumerID), root) {
		t.Fatalf("consumer identifiers are not stable opaque values: %#v", recent)
	}
}

type recordingSink struct {
	mu     sync.Mutex
	events []events.Event
	err    error
}

func (sink *recordingSink) Append(event events.Event) error {
	if err := event.Validate(); err != nil {
		return err
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	sink.events = append(sink.events, event)
	return sink.err
}

func (sink *recordingSink) contains(operation events.Operation, outcome events.Outcome) bool {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	for _, event := range sink.events {
		if event.Operation == operation && event.Outcome == outcome {
			return true
		}
	}
	return false
}

func openEmptyManager(t *testing.T, root, upstreamPath string, sink EventSink) *Manager {
	t.Helper()
	manager, err := Open(configuration(upstreamPath), sink)
	if err != nil {
		t.Fatalf("Open(): %v", err)
	}
	return manager
}

func configuration(upstream string, consumers ...config.Consumer) config.Config {
	return config.Config{Upstream: upstream, Consumers: consumers, Timeouts: shortTimeouts()}
}

func consumer(name, socket string, group *uint32, fingerprints ...string) config.Consumer {
	return config.Consumer{Name: name, Socket: socket, AccessGroup: group, Fingerprints: fingerprints}
}

func shortTimeouts() config.Timeouts {
	timeouts := config.DefaultTimeouts()
	timeouts.Connect = 100 * time.Millisecond
	timeouts.List = 500 * time.Millisecond
	timeouts.Replay = 500 * time.Millisecond
	timeouts.Sign = time.Second
	return timeouts
}

func generateKey(t *testing.T) (ssh.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	return key, private
}

type agentServer struct {
	listener *net.UnixListener
	agent    agent.Agent
	mu       sync.Mutex
	clients  map[*net.UnixConn]struct{}
	wg       sync.WaitGroup
}

func startAgentServer(t *testing.T, path string, privateKeys ...ed25519.PrivateKey) *agentServer {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	keyring := agent.NewKeyring()
	for index, key := range privateKeys {
		if err := keyring.Add(agent.AddedKey{PrivateKey: key, Comment: "label"}); err != nil {
			t.Fatal(err)
		}
		_ = index
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	server := &agentServer{listener: listener, agent: keyring, clients: make(map[*net.UnixConn]struct{})}
	server.wg.Add(1)
	go func() {
		defer server.wg.Done()
		for {
			connection, acceptErr := listener.AcceptUnix()
			if acceptErr != nil {
				return
			}
			server.mu.Lock()
			server.clients[connection] = struct{}{}
			server.mu.Unlock()
			server.wg.Add(1)
			go func() {
				defer server.wg.Done()
				_ = agent.ServeAgent(server.agent, connection)
				_ = connection.Close()
				server.mu.Lock()
				delete(server.clients, connection)
				server.mu.Unlock()
			}()
		}
	}()
	return server
}

func (server *agentServer) close(t *testing.T) {
	t.Helper()
	_ = server.listener.Close()
	server.mu.Lock()
	for connection := range server.clients {
		_ = connection.Close()
	}
	server.mu.Unlock()
	server.wg.Wait()
}

func (server *agentServer) clientCount() int {
	server.mu.Lock()
	defer server.mu.Unlock()
	return len(server.clients)
}

func assertListedFingerprints(t *testing.T, client agent.Agent, want []string) {
	t.Helper()
	keys, err := client.List()
	if err != nil {
		t.Fatalf("List(): %v", err)
	}
	if got := fingerprints(keys); !slices.Equal(got, want) {
		t.Fatalf("fingerprints = %v, want %v", got, want)
	}
}

func fingerprints(keys []*agent.Key) []string {
	result := make([]string, len(keys))
	for index, key := range keys {
		result[index] = ssh.FingerprintSHA256(key)
	}
	return result
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(%s): %v", filepath.Base(path), err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("%s mode = %04o, want %04o", filepath.Base(path), got, want)
	}
}

func testFingerprint(value byte) string {
	return "SHA256:" + base64RawDigest(value)
}

func base64RawDigest(value byte) string {
	digest := make([]byte, 32)
	for index := range digest {
		digest[index] = value
	}
	return base64.RawStdEncoding.EncodeToString(digest)
}

func closeManager(t *testing.T, manager *Manager) {
	t.Helper()
	if err := manager.Close(); err != nil {
		t.Errorf("Close(): %v", err)
	}
}

type temporaryFixtureError struct{}

func (temporaryFixtureError) Error() string   { return "temporary fixture error" }
func (temporaryFixtureError) Timeout() bool   { return false }
func (temporaryFixtureError) Temporary() bool { return true }

func assertFDOpen(t *testing.T, fd int) {
	t.Helper()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		t.Fatalf("fd %d is not open: %v", fd, err)
	}
}

func assertFDClosed(t *testing.T, fd int) {
	t.Helper()
	if fd < 0 {
		t.Fatalf("invalid fixture fd %d", fd)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); !errors.Is(err, unix.EBADF) {
		t.Fatalf("fd %d remained open: %v", fd, err)
	}
}
