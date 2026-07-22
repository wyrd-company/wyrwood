//go:build linux

// ---
// relationships:
//   verifies: control-interface
//   verifies: configuration
// ---

package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/wyrd-company/wyrwood/internal/config"
	"github.com/wyrd-company/wyrwood/internal/control"
)

func TestConfigurationControlReadsMutatesAndAppliesDistinctRevisions(t *testing.T) {
	fixture := newFixture(t)
	firstSocket := filepath.Join(fixture.root, "first", "agent.sock")
	secondSocket := filepath.Join(fixture.root, "second", "agent.sock")
	fixture.writeConfig(firstSocket, secondSocket)
	initialBytes, _ := os.ReadFile(fixture.options.ConfigPath)
	initialRevision := configurationRevision(initialBytes)
	service, err := Open(fixture.options)
	if err != nil {
		t.Fatalf("Open(): %v", err)
	}
	defer service.Close()
	client, _ := control.NewClient(fixture.options.ControlPath)

	first, err := client.Configuration(0, 1, "")
	if err != nil {
		t.Fatalf("Configuration(first): %v", err)
	}
	if first.Revision != initialRevision || first.Offset != 0 || first.TotalConsumers != 2 || first.Complete || len(first.Consumers) != 1 {
		t.Fatalf("first page = %#v", first)
	}
	second, err := client.Configuration(1, 1, first.Revision)
	if err != nil || !second.Complete || len(second.Consumers) != 1 || second.Consumers[0].Socket <= first.Consumers[0].Socket {
		t.Fatalf("second page = %#v, %v", second, err)
	}

	newUpstream := filepath.Join(fixture.root, "replacement", "agent.sock")
	changed, err := client.SetUpstream(initialRevision, newUpstream)
	if err != nil || !changed.Changed || changed.Revision == initialRevision {
		t.Fatalf("SetUpstream() = %#v, %v", changed, err)
	}
	status, err := client.Status()
	if err != nil || status.ActiveRevision != initialRevision {
		t.Fatalf("Status() active revision = %#v, %v, want durable/runtime separation", status, err)
	}
	page, err := client.Configuration(0, 16, "")
	if err != nil || page.Revision != changed.Revision || page.Upstream != newUpstream {
		t.Fatalf("Configuration(after mutation) = %#v, %v", page, err)
	}
	if _, err := client.Configuration(1, 1, initialRevision); !remoteCode(err, control.ErrorConfigurationConflict) {
		t.Fatalf("stale page error = %v", err)
	}
	apply, err := client.Apply()
	if err != nil || !apply.Committed || apply.Revision != changed.Revision {
		t.Fatalf("Apply() = %#v, %v", apply, err)
	}
	status, err = client.Status()
	if err != nil || status.ActiveRevision != changed.Revision {
		t.Fatalf("Status() after apply = %#v, %v", status, err)
	}

	data, err := os.ReadFile(fixture.options.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 || data[len(data)-1] != '\n' || strings.Contains(string(data), "\r\n") {
		t.Fatalf("managed YAML is not canonical: %q", data)
	}
	info, _ := os.Stat(fixture.options.ConfigPath)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("managed configuration mode = %o", info.Mode().Perm())
	}
}

func TestConfigurationControlProjectsAccessGroupAndUnifiedConsumerIdentity(t *testing.T) {
	fixture := newFixture(t)
	socket := filepath.Join(fixture.root, "first", "agent.sock")
	fixture.writeConfig(socket)
	service, err := Open(fixture.options)
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	client, _ := control.NewClient(fixture.options.ControlPath)
	page, _ := client.Configuration(0, 16, "")
	oldID := page.Consumers[0].ID
	group := uint32(os.Getegid())
	newSocket := filepath.Join(fixture.root, "replacement", "agent.sock")
	change, err := client.PutConsumer(page.Revision, &oldID, control.ConfigurationConsumerInput{
		Name: "replacement", Socket: newSocket, AccessGroup: &group, Fingerprints: []string{testFingerprint(4)},
	})
	if err != nil || change.ConsumerID == nil || *change.ConsumerID != consumerIdentifier(newSocket) || *change.ConsumerID == oldID {
		t.Fatalf("PutConsumer() = %#v, %v", change, err)
	}
	page, err = client.Configuration(0, 16, "")
	if err != nil || page.Consumers[0].AccessGroup == nil || *page.Consumers[0].AccessGroup != group {
		t.Fatalf("access_group projection = %#v, %v", page, err)
	}
	if _, err := client.Apply(); err != nil {
		t.Fatalf("Apply(): %v", err)
	}
	status, _ := client.Status()
	if len(status.Consumers) != 1 || status.Consumers[0].ID != *change.ConsumerID {
		t.Fatalf("status identity = %#v, want %s", status.Consumers, *change.ConsumerID)
	}
	events, _ := client.Events(control.MaximumEventLimit)
	found := false
	for _, event := range events.Events {
		found = found || event.ConsumerID == *change.ConsumerID
	}
	if !found {
		t.Fatalf("event identity did not include %s: %#v", *change.ConsumerID, events.Events)
	}
}

func TestConfigurationControlSerializesWritersAndRejectsStaleOrInvalidCandidates(t *testing.T) {
	fixture := newFixture(t)
	socket := filepath.Join(fixture.root, "first", "agent.sock")
	fixture.writeConfig(socket)
	service, err := Open(fixture.options)
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	client, _ := control.NewClient(fixture.options.ControlPath)
	page, _ := client.Configuration(0, 16, "")

	results := make(chan error, 2)
	var start sync.WaitGroup
	start.Add(2)
	for _, name := range []string{"one", "two"} {
		name := name
		go func() {
			start.Done()
			start.Wait()
			_, err := client.SetUpstream(page.Revision, filepath.Join(fixture.root, name, "agent.sock"))
			results <- err
		}()
	}
	successes, conflicts := 0, 0
	for range 2 {
		err := <-results
		if err == nil {
			successes++
		} else if remoteCode(err, control.ErrorConfigurationConflict) {
			conflicts++
		} else {
			t.Fatalf("concurrent mutation error = %v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("concurrent outcomes = success %d, conflict %d", successes, conflicts)
	}

	page, _ = client.Configuration(0, 16, "")
	if _, err := client.SetUpstream(page.Revision, socket); !remoteCode(err, control.ErrorConfigurationInvalid) {
		t.Fatalf("duplicate upstream candidate error = %v", err)
	}
	bad := control.ConfigurationTimeouts{Connect: "99ms", List: "5s", Replay: "5s", Sign: "2m"}
	if _, err := client.SetTimeouts(page.Revision, bad); !remoteCode(err, control.ErrorConfigurationInvalid) {
		t.Fatalf("invalid timeout candidate error = %v", err)
	}
	missing := strings.Repeat("f", 64)
	if _, err := client.RetireConsumer(page.Revision, missing); !remoteCode(err, control.ErrorConfigurationNotFound) {
		t.Fatalf("missing consumer error = %v", err)
	}
}

func TestConfigurationControlReportsDurabilityUncertaintyAndMakesRetrySafe(t *testing.T) {
	fixture := newFixture(t)
	fixture.writeConfig(filepath.Join(fixture.root, "first", "agent.sock"))
	service, err := Open(fixture.options)
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	client, _ := control.NewClient(fixture.options.ControlPath)
	page, _ := client.Configuration(0, 16, "")
	service.publication.syncDirectory = func(int) error { return errors.New("injected directory sync failure") }
	upstream := filepath.Join(fixture.root, "replacement", "agent.sock")
	if _, err := client.SetUpstream(page.Revision, upstream); !remoteCode(err, control.ErrorConfigurationDurabilityUncertain) {
		t.Fatalf("SetUpstream() error = %v", err)
	}
	service.publication = defaultPublicationDependencies()
	current, err := client.Configuration(0, 16, "")
	if err != nil || current.Upstream != upstream || current.Revision == page.Revision {
		t.Fatalf("post-uncertainty configuration = %#v, %v", current, err)
	}
	if _, err := client.SetUpstream(page.Revision, upstream); !remoteCode(err, control.ErrorConfigurationConflict) {
		t.Fatalf("retry with uncertain predecessor error = %v", err)
	}
	retry, err := client.SetUpstream(current.Revision, upstream)
	if err != nil || retry.Changed || retry.Revision != current.Revision {
		t.Fatalf("refetched idempotent retry = %#v, %v", retry, err)
	}
}

func TestConfigurationControlDetectsDirectEditImmediatelyBeforeRename(t *testing.T) {
	fixture := newFixture(t)
	fixture.writeConfig(filepath.Join(fixture.root, "first", "agent.sock"))
	service, err := Open(fixture.options)
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	client, _ := control.NewClient(fixture.options.ControlPath)
	page, _ := client.Configuration(0, 16, "")
	direct := []byte(strings.Replace(string(mustRead(t, fixture.options.ConfigPath)), "name: first", "name: edited", 1))
	service.publication.beforeRename = func() {
		if err := os.WriteFile(fixture.options.ConfigPath, direct, 0o600); err != nil {
			t.Errorf("direct edit: %v", err)
		}
	}
	if _, err := client.SetUpstream(page.Revision, filepath.Join(fixture.root, "replacement", "agent.sock")); !remoteCode(err, control.ErrorConfigurationConflict) {
		t.Fatalf("SetUpstream() error = %v", err)
	}
	if got := mustRead(t, fixture.options.ConfigPath); string(got) != string(direct) {
		t.Fatal("managed mutation overwrote intervening direct edit")
	}
}

func TestConfigurationPublicationRejectsOversizeBeforeCreatingTemporaryFile(t *testing.T) {
	fixture := newFixture(t)
	fixture.writeConfig(filepath.Join(fixture.root, "first", "agent.sock"))
	directory, err := openConfigurationDirectory(fixture.options.ConfigPath, fixture.options.UID)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.close()
	loaded, err := directory.read(nil)
	if err != nil {
		t.Fatal(err)
	}
	published, err := directory.replace(loaded.revision, make([]byte, config.MaximumDocumentBytes+1), defaultPublicationDependencies())
	var invalid *invalidConfigurationError
	if published || !errors.As(err, &invalid) {
		t.Fatalf("replace(oversize) = published %v, error %v", published, err)
	}
	entries, err := os.ReadDir(filepath.Dir(fixture.options.ConfigPath))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != filepath.Base(fixture.options.ConfigPath) {
		t.Fatalf("oversize replacement created filesystem artifacts: %#v", entries)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
