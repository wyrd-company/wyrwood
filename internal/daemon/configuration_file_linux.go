//go:build linux

// ---
// relationships:
//   implements: control-interface
//   uses: configuration
// ---

package daemon

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/wyrd-company/wyrwood/internal/config"
	"golang.org/x/sys/unix"
)

var errConfigurationNotFound = errors.New("configuration not found")

type invalidConfigurationError struct{ err error }

func (err *invalidConfigurationError) Error() string { return "invalid configuration" }
func (err *invalidConfigurationError) Unwrap() error { return err.err }

type loadedConfiguration struct {
	value    config.Config
	bytes    []byte
	revision string
}

type configurationDirectory struct {
	fd   int
	base string
	uid  uint32
}

func openConfigurationDirectory(path string, uid uint32) (*configurationDirectory, error) {
	if strings.IndexByte(path, 0) >= 0 || !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Dir(path) == string(filepath.Separator) {
		return nil, errors.New("configuration path must be canonical, absolute, and use a dedicated directory")
	}
	fd, err := unix.Open(filepath.Dir(path), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil, errConfigurationNotFound
		}
		return nil, errors.New("open configuration directory")
	}
	var status unix.Stat_t
	if err := unix.Fstat(fd, &status); err != nil || status.Uid != uid || status.Mode&unix.S_IFMT != unix.S_IFDIR || status.Mode&0o7777 != 0o700 {
		_ = unix.Close(fd)
		return nil, errors.New("configuration directory must be owner-only")
	}
	return &configurationDirectory{fd: fd, base: filepath.Base(path), uid: uid}, nil
}

func (directory *configurationDirectory) close() { _ = unix.Close(directory.fd) }

func (directory *configurationDirectory) read(afterFileOpen func()) (loadedConfiguration, error) {
	fd, err := unix.Openat(directory.fd, directory.base, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return loadedConfiguration{}, errConfigurationNotFound
		}
		return loadedConfiguration{}, errors.New("open configuration file")
	}
	file := os.NewFile(uintptr(fd), directory.base)
	if file == nil {
		_ = unix.Close(fd)
		return loadedConfiguration{}, errors.New("own configuration file descriptor")
	}
	defer file.Close()
	var status unix.Stat_t
	if err := unix.Fstat(fd, &status); err != nil || status.Uid != directory.uid || status.Mode&unix.S_IFMT != unix.S_IFREG || status.Mode&0o7777 != 0o600 {
		return loadedConfiguration{}, errors.New("configuration file must be owner-only and regular")
	}
	if afterFileOpen != nil {
		afterFileOpen()
	}
	data, err := io.ReadAll(io.LimitReader(file, config.MaximumDocumentBytes+1))
	if err != nil {
		return loadedConfiguration{}, errors.New("read configuration file")
	}
	value, err := config.Parse(data)
	if err != nil {
		return loadedConfiguration{}, &invalidConfigurationError{err: err}
	}
	return loadedConfiguration{value: value, bytes: data, revision: configurationRevision(data)}, nil
}

func loadConfigurationDocument(path string, uid uint32, afterFileOpen func()) (loadedConfiguration, error) {
	directory, err := openConfigurationDirectory(path, uid)
	if err != nil {
		return loadedConfiguration{}, err
	}
	defer directory.close()
	return directory.read(afterFileOpen)
}

func loadConfiguration(path string, uid uint32) (config.Config, error) {
	return loadConfigurationWithHook(path, uid, nil)
}

func loadConfigurationWithHook(path string, uid uint32, afterFileOpen func()) (config.Config, error) {
	loaded, err := loadConfigurationDocument(path, uid, afterFileOpen)
	return loaded.value, err
}

func configurationRevision(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func consumerIdentifier(path string) string {
	digest := sha256.Sum256([]byte(path))
	return hex.EncodeToString(digest[:])
}

type publicationDependencies struct {
	syncDirectory func(int) error
	beforeVerify  func()
	beforeRename  func()
}

func defaultPublicationDependencies() publicationDependencies {
	return publicationDependencies{syncDirectory: unix.Fsync}
}

// replace publishes candidate only while the exact predecessor revision still
// occupies the fixed path. A successful rename is never reported as rolled
// back when the subsequent directory durability confirmation fails.
func (directory *configurationDirectory) replace(expectedRevision string, candidate []byte, deps publicationDependencies) (bool, error) {
	if len(candidate) > config.MaximumDocumentBytes {
		return false, &invalidConfigurationError{err: errors.New("canonical configuration exceeds the supported size")}
	}
	if deps.beforeVerify != nil {
		deps.beforeVerify()
	}
	current, err := directory.read(nil)
	if err != nil {
		return false, err
	}
	if current.revision != expectedRevision {
		return false, errConfigurationConflict
	}
	if string(current.bytes) == string(candidate) {
		return false, nil
	}

	temporaryName, fd, err := directory.createTemporary()
	if err != nil {
		return false, err
	}
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = unix.Unlinkat(directory.fd, temporaryName, 0)
		}
	}()
	file := os.NewFile(uintptr(fd), temporaryName)
	if file == nil {
		_ = unix.Close(fd)
		return false, errors.New("own temporary configuration")
	}
	if _, err := file.Write(candidate); err != nil {
		_ = file.Close()
		return false, errors.New("write temporary configuration")
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return false, errors.New("sync temporary configuration")
	}
	if err := file.Close(); err != nil {
		return false, errors.New("close temporary configuration")
	}
	if deps.beforeRename != nil {
		deps.beforeRename()
	}
	// Close the ordinary direct-edit window as tightly as the filesystem API
	// permits by repeating the exact-byte precondition immediately before rename.
	current, err = directory.read(nil)
	if err != nil {
		return false, err
	}
	if current.revision != expectedRevision {
		return false, errConfigurationConflict
	}
	if err := unix.Renameat(directory.fd, temporaryName, directory.fd, directory.base); err != nil {
		return false, errors.New("publish configuration")
	}
	removeTemporary = false
	if err := deps.syncDirectory(directory.fd); err != nil {
		return true, errors.New("sync configuration directory")
	}
	return true, nil
}

var errConfigurationConflict = errors.New("configuration revision conflict")

func (directory *configurationDirectory) createTemporary() (string, int, error) {
	for attempts := 0; attempts < 8; attempts++ {
		var random [12]byte
		if _, err := rand.Read(random[:]); err != nil {
			return "", -1, errors.New("generate temporary configuration name")
		}
		name := ".config-" + hex.EncodeToString(random[:])
		fd, err := unix.Openat(directory.fd, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
		if err == nil {
			if err := unix.Fchmod(fd, 0o600); err != nil {
				_ = unix.Close(fd)
				_ = unix.Unlinkat(directory.fd, name, 0)
				return "", -1, errors.New("secure temporary configuration")
			}
			var status unix.Stat_t
			if unix.Fstat(fd, &status) != nil || status.Uid != directory.uid || status.Mode&unix.S_IFMT != unix.S_IFREG || status.Mode&0o7777 != 0o600 {
				_ = unix.Close(fd)
				_ = unix.Unlinkat(directory.fd, name, 0)
				return "", -1, errors.New("temporary configuration ownership or mode verification failed")
			}
			return name, fd, nil
		}
		if !errors.Is(err, unix.EEXIST) {
			return "", -1, errors.New("create temporary configuration")
		}
	}
	return "", -1, errors.New("allocate temporary configuration name")
}
