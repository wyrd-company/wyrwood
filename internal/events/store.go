// ---
// relationships:
//   implements: operational-events
// ---

package events

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/sys/unix"
)

const maximumRetention = 100_000

var (
	// ErrCorrupt means corruption occurred outside the recoverable final-frame boundary.
	ErrCorrupt = errors.New("operational event store is corrupt")
	// ErrWriterActive means another daemon writer holds the store lock.
	ErrWriterActive = errors.New("operational event store already has a writer")
	// ErrClosed means the store no longer accepts operations.
	ErrClosed = errors.New("operational event store is closed")
)

// Store is one bounded durable event history with a single daemon writer.
type Store struct {
	mu        sync.RWMutex
	path      string
	retention int
	lock      *os.File
	file      *os.File
	events    []Event
	closed    bool
}

// Open creates or recovers the store at the explicit absolute path. The
// path's parent directory is dedicated to event storage and is made owner-only.
func Open(path string, retention int) (*Store, error) {
	return openWithRemove(path, retention, os.Remove)
}

func openWithRemove(path string, retention int, remove func(string) error) (*Store, error) {
	if err := validateStorageInputs(path, retention); err != nil {
		return nil, err
	}
	directory := filepath.Dir(path)
	if err := ensureOwnerOnlyDirectory(directory); err != nil {
		return nil, err
	}
	lock, err := openOwnerOnlyFile(path+".lock", unix.O_RDWR|unix.O_CREAT)
	if err != nil {
		return nil, fmt.Errorf("open event writer lock: %w", err)
	}
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = lock.Close()
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, ErrWriterActive
		}
		return nil, fmt.Errorf("lock event writer: %w", err)
	}
	if err := cleanupStaleReplacements(directory, remove); err != nil {
		_ = lock.Close()
		return nil, fmt.Errorf("clean stale event replacements: %w", err)
	}

	file, err := openOwnerOnlyFile(path, unix.O_RDWR|unix.O_CREAT|unix.O_APPEND)
	if err != nil {
		_ = lock.Close()
		return nil, fmt.Errorf("open event store: %w", err)
	}
	store := &Store{path: path, retention: retention, lock: lock, file: file}
	if err := store.initialize(); err != nil {
		_ = store.file.Close()
		_ = lock.Close()
		return nil, err
	}
	return store, nil
}

func (store *Store) initialize() error {
	events, recoverOffset, err := loadFrames(store.file)
	if err != nil {
		return err
	}
	info, err := store.file.Stat()
	if err != nil {
		return fmt.Errorf("inspect event store: %w", err)
	}
	if info.Size() == 0 {
		if _, err := store.file.Write([]byte(fileMagic)); err != nil {
			return fmt.Errorf("initialize event store: %w", err)
		}
		if err := store.syncFileAndDirectory(); err != nil {
			return err
		}
	}
	if recoverOffset >= 0 {
		if err := store.file.Truncate(recoverOffset); err != nil {
			return fmt.Errorf("remove interrupted final event: %w", err)
		}
		if err := store.file.Sync(); err != nil {
			return fmt.Errorf("sync recovered event store: %w", err)
		}
	}
	store.events = events
	if len(store.events) > store.retention {
		store.events = cloneEvents(store.events[len(store.events)-store.retention:])
		if err := store.replace(); err != nil {
			return fmt.Errorf("compact recovered event store: %w", err)
		}
	}
	return nil
}

// Append durably records one validated event before returning. A failed write
// closes the store so a later Open can recover the final frame before reuse.
func (store *Store) Append(event Event) error {
	event, err := normalizeEvent(event)
	if err != nil {
		return err
	}
	frame, err := encodeFrame(event)
	if err != nil {
		return err
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closed {
		return ErrClosed
	}
	if _, err := store.file.Write(frame); err != nil {
		store.closeAfterWriteFailure()
		return fmt.Errorf("append event: %w", err)
	}
	if err := store.file.Sync(); err != nil {
		store.closeAfterWriteFailure()
		return fmt.Errorf("sync appended event: %w", err)
	}
	store.events = append(store.events, event)
	if len(store.events) <= store.retention {
		return nil
	}
	store.events = cloneEvents(store.events[len(store.events)-store.retention:])
	if err := store.replace(); err != nil {
		store.closeAfterWriteFailure()
		return fmt.Errorf("compact event store: %w", err)
	}
	return nil
}

// Close flushes durable state and releases the single-writer lock.
func (store *Store) Close() error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closed {
		return nil
	}
	store.closed = true
	var result error
	if err := store.file.Sync(); err != nil {
		result = errors.Join(result, fmt.Errorf("sync event store: %w", err))
	}
	if err := store.file.Close(); err != nil {
		result = errors.Join(result, fmt.Errorf("close event store: %w", err))
	}
	if err := store.lock.Close(); err != nil {
		result = errors.Join(result, fmt.Errorf("close event writer lock: %w", err))
	}
	return result
}

func (store *Store) replace() error {
	directory := filepath.Dir(store.path)
	temporary, err := os.CreateTemp(directory, replacementPrefix+"*")
	if err != nil {
		return fmt.Errorf("create replacement: %w", err)
	}
	temporaryPath := temporary.Name()
	cleanup := func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
	}
	if err := temporary.Chmod(0o600); err != nil {
		cleanup()
		return fmt.Errorf("secure replacement: %w", err)
	}
	if _, err := temporary.Write([]byte(fileMagic)); err != nil {
		cleanup()
		return fmt.Errorf("write replacement header: %w", err)
	}
	for _, event := range store.events {
		frame, frameErr := encodeFrame(event)
		if frameErr != nil {
			cleanup()
			return fmt.Errorf("encode replacement event: %w", frameErr)
		}
		if _, err := temporary.Write(frame); err != nil {
			cleanup()
			return fmt.Errorf("write replacement event: %w", err)
		}
	}
	if err := temporary.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("sync replacement: %w", err)
	}
	if err := temporary.Close(); err != nil {
		_ = os.Remove(temporaryPath)
		return fmt.Errorf("close replacement: %w", err)
	}
	if err := os.Rename(temporaryPath, store.path); err != nil {
		_ = os.Remove(temporaryPath)
		return fmt.Errorf("publish replacement: %w", err)
	}
	newFile, err := openOwnerOnlyFile(store.path, unix.O_RDWR|unix.O_APPEND)
	if err != nil {
		return fmt.Errorf("reopen replacement: %w", err)
	}
	oldFile := store.file
	store.file = newFile
	if err := oldFile.Close(); err != nil {
		return fmt.Errorf("close replaced event store: %w", err)
	}
	if err := syncDirectory(directory); err != nil {
		return fmt.Errorf("sync replacement directory: %w", err)
	}
	return nil
}

func (store *Store) closeAfterWriteFailure() {
	store.closed = true
	_ = store.file.Close()
	_ = store.lock.Close()
}

func cloneEvents(source []Event) []Event {
	result := make([]Event, len(source))
	for index, event := range source {
		result[index] = cloneEvent(event)
	}
	return result
}

func (store *Store) syncFileAndDirectory() error {
	if err := store.file.Sync(); err != nil {
		return fmt.Errorf("sync event store: %w", err)
	}
	if err := syncDirectory(filepath.Dir(store.path)); err != nil {
		return fmt.Errorf("sync event store directory: %w", err)
	}
	return nil
}
