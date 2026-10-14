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

	"golang.org/x/crypto/ssh"
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
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, fmt.Errorf("create host key directory: %w", err)
		}
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
