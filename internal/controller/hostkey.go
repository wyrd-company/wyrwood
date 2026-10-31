// ---
// relationships:
//   implements: controller
// ---

package controller

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

// HostKeyPath returns the SSH host key location under a state directory. The
// key lives in its own subdirectory so it can be a separate volume.
func HostKeyPath(stateDirectory string) string {
	return filepath.Join(stateDirectory, "ssh", "ssh_host_ed25519_key")
}

// LoadOrCreateHostKey returns the controller host key, generating it with
// owner-only mode on first start.
func LoadOrCreateHostKey(stateDirectory string) (ssh.Signer, error) {
	path := HostKeyPath(stateDirectory)
	if err := prepareHostKeyDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		_, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		block, err := ssh.MarshalPrivateKey(private, "wyrwood controller")
		if err != nil {
			return nil, err
		}
		data = pem.EncodeToMemory(block)
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return nil, fmt.Errorf("create host key: %w", err)
		}
		if _, err := file.Write(data); err != nil {
			_ = file.Close()
			return nil, fmt.Errorf("write host key: %w", err)
		}
		if err := file.Sync(); err != nil {
			_ = file.Close()
			return nil, err
		}
		if err := file.Close(); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, fmt.Errorf("read host key: %w", err)
	}
	signer, err := ssh.ParsePrivateKey(data)
	if err != nil {
		return nil, errors.New("host key is not a valid private key")
	}
	return signer, nil
}

// Only the exact broken mode produced by the former control-socket umask is
// repaired. Pin the real, owned leaf before changing permissions; never chmod
// a pathname that could be replaced with a symlink.
func prepareHostKeyDirectory(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open host key directory: %w", err)
	}
	directory := os.NewFile(uintptr(fd), path)
	defer directory.Close()
	info, err := directory.Stat()
	if err != nil {
		return err
	}
	status, ok := info.Sys().(*syscall.Stat_t)
	if !ok || status.Uid != uint32(os.Geteuid()) {
		return errors.New("host key directory must be owned by the controller user")
	}
	if info.Mode().Perm() == 0o600 && info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) == 0 {
		if err := directory.Chmod(0o700); err != nil {
			return fmt.Errorf("repair host key directory: %w", err)
		}
	}
	return nil
}

// HostKeyFingerprint reads the existing host key and returns its fingerprint
// without creating one.
func HostKeyFingerprint(stateDirectory string) (string, error) {
	data, err := os.ReadFile(HostKeyPath(stateDirectory))
	if err != nil {
		return "", err
	}
	signer, err := ssh.ParsePrivateKey(data)
	if err != nil {
		return "", errors.New("host key is not a valid private key")
	}
	return ssh.FingerprintSHA256(signer.PublicKey()), nil
}
