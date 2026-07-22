// ---
// relationships:
//   verifies: operational-events
// ---

package events

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"hash/crc32"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
)

func TestStoreRetentionSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "events.bin")
	store, err := Open(path, 3)
	if err != nil {
		t.Fatalf("Open(): %v", err)
	}
	for sequence := 1; sequence <= 5; sequence++ {
		if err := store.Append(sampleEvent(sequence)); err != nil {
			t.Fatalf("Append(%d): %v", sequence, err)
		}
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close(): %v", err)
	}

	reopened, err := Open(path, 3)
	if err != nil {
		t.Fatalf("Open(restart): %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	recent := reopened.Recent(10)
	if len(recent) != 3 {
		t.Fatalf("Recent() length = %d, want 3", len(recent))
	}
	for index, sequence := range []int{3, 4, 5} {
		if !recent[index].Timestamp.Equal(sampleEvent(sequence).Timestamp) {
			t.Errorf("Recent()[%d] timestamp = %v, want sequence %d", index, recent[index].Timestamp, sequence)
		}
	}
}

func TestStoreRecoversInterruptedFinalFrame(t *testing.T) {
	path := initializedStorePath(t)
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	frame, err := encodeFrame(sampleEvent(2))
	if err != nil {
		t.Fatal(err)
	}
	appendBytes(t, path, frame[:5])

	store, err := Open(path, 4)
	if err != nil {
		t.Fatalf("Open(crash tail): %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if got := len(store.Recent(10)); got != 1 {
		t.Fatalf("Recent() length = %d, want 1", got)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if after.Size() != before.Size() {
		t.Errorf("recovered size = %d, want %d", after.Size(), before.Size())
	}
}

func TestStoreRecoversInterruptedFinalBody(t *testing.T) {
	path := initializedStorePath(t)
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	frame, err := encodeFrame(sampleEvent(2))
	if err != nil {
		t.Fatal(err)
	}
	appendBytes(t, path, frame[:frameHeaderBytes+len(frame[frameHeaderBytes:])/2])

	store, err := Open(path, 4)
	if err != nil {
		t.Fatalf("Open(incomplete body): %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if got := len(store.Recent(10)); got != 1 {
		t.Fatalf("Recent() length = %d, want 1", got)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if after.Size() != before.Size() {
		t.Errorf("recovered size = %d, want %d", after.Size(), before.Size())
	}
}

func TestStoreRecoversChecksumInvalidFinalFrame(t *testing.T) {
	path := initializedStorePath(t)
	frame, err := encodeFrame(sampleEvent(2))
	if err != nil {
		t.Fatal(err)
	}
	frame[len(frame)-1] ^= 0xff
	appendBytes(t, path, frame)

	store, err := Open(path, 4)
	if err != nil {
		t.Fatalf("Open(checksum-invalid tail): %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if got := len(store.Recent(10)); got != 1 {
		t.Fatalf("Recent() length = %d, want 1", got)
	}
}

func TestStoreRejectsCorruptionBeforeFinalFrame(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "events.bin")
	store, err := Open(path, 4)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Append(sampleEvent(1)); err != nil {
		t.Fatal(err)
	}
	if err := store.Append(sampleEvent(2)); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data[len(fileMagic)+frameHeaderBytes+1] ^= 0xff
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Open(path, 4); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Open(corrupt interior) error = %v, want ErrCorrupt", err)
	}
}

func TestStoreRejectsChecksumValidInvalidFinalEvent(t *testing.T) {
	path := initializedStorePath(t)
	event := sampleEvent(2)
	frame, err := encodeFrame(event)
	if err != nil {
		t.Fatal(err)
	}
	var record map[string]any
	if err := json.Unmarshal(frame[frameHeaderBytes:], &record); err != nil {
		t.Fatal(err)
	}
	delete(record, "latency")
	payload, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	frame = make([]byte, frameHeaderBytes+len(payload))
	binary.BigEndian.PutUint32(frame[0:4], uint32(len(payload)))
	binary.BigEndian.PutUint32(frame[4:8], crc32.Checksum(payload, checksumTable))
	copy(frame[frameHeaderBytes:], payload)
	appendBytes(t, path, frame)

	if _, err := Open(path, 4); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Open(schema-invalid tail) error = %v, want ErrCorrupt", err)
	}
}

func TestStoreUsesOwnerOnlyModesAndRejectsSecondWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "events.bin")
	store, err := Open(path, 4)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	for _, check := range []struct {
		path string
		mode os.FileMode
	}{
		{filepath.Dir(path), 0o700},
		{path, 0o600},
		{path + ".lock", 0o600},
	} {
		info, err := os.Stat(check.path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != check.mode {
			t.Errorf("%s mode = %#o, want %#o", check.path, got, check.mode)
		}
	}
	if _, err := Open(path, 4); !errors.Is(err, ErrWriterActive) {
		t.Fatalf("Open(second writer) error = %v, want ErrWriterActive", err)
	}
}

func TestOpenRejectsInvalidStorageInputs(t *testing.T) {
	t.Parallel()

	for name, open := range map[string]func() error{
		"relative-path": func() error {
			_, err := Open(filepath.Join("relative", "events.bin"), 4)
			return err
		},
		"zero-retention": func() error {
			_, err := Open(filepath.Join(t.TempDir(), "events.bin"), 0)
			return err
		},
		"excessive-retention": func() error {
			_, err := Open(filepath.Join(t.TempDir(), "events.bin"), maximumRetention+1)
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := open(); err == nil {
				t.Fatal("Open() error = nil")
			}
		})
	}
}

func TestRetentionUsesAtomicReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "events.bin")
	store, err := Open(path, 2)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Append(sampleEvent(1)); err != nil {
		t.Fatal(err)
	}
	before := inode(t, path)
	if err := store.Append(sampleEvent(2)); err != nil {
		t.Fatal(err)
	}
	if err := store.Append(sampleEvent(3)); err != nil {
		t.Fatal(err)
	}
	after := inode(t, path)
	if before == after {
		t.Errorf("event store inode did not change across retention replacement")
	}
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".events-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Errorf("replacement temporary files remain: %v", matches)
	}
}

func TestStoreConcurrentAppendAndQueries(t *testing.T) {
	store := openTestStore(t, 256)
	t.Cleanup(func() { _ = store.Close() })

	const count = 100
	var wait sync.WaitGroup
	for sequence := 1; sequence <= count; sequence++ {
		sequence := sequence
		wait.Add(1)
		go func() {
			defer wait.Done()
			if err := store.Append(sampleEvent(sequence)); err != nil {
				t.Errorf("Append(%d): %v", sequence, err)
			}
			_ = store.Recent(8)
			_ = store.LastConsumerActivity()
			_ = store.ConsumerHealth()
			_ = store.Health()
		}()
	}
	wait.Wait()
	if got := len(store.Recent(count + 1)); got != count {
		t.Fatalf("Recent() length = %d, want %d", got, count)
	}
}

func initializedStorePath(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state", "events.bin")
	store, err := Open(path, 4)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Append(sampleEvent(1)); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func openTestStore(t *testing.T, retention int) *Store {
	t.Helper()
	store, err := Open(filepath.Join(t.TempDir(), "state", "events.bin"), retention)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func appendBytes(t *testing.T, path string, data []byte) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func inode(t *testing.T, path string) uint64 {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	status, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("inode metadata unavailable")
	}
	return status.Ino
}
