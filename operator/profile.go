// ---
// relationships:
//   implements: operator-interface
// ---

package operator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
)

// Profile is a saved login: the controller, its pinned host key, and how to
// reach the key. It holds no private key.
type Profile struct {
	URL     string `json:"url"`
	HostKey string `json:"host-key"`
	Label   string `json:"label,omitempty"`
	// KeyFile is the path of a key this package generated or loaded.
	KeyFile string `json:"key-file,omitempty"`
	// AgentKey selects one key of the SSH agent at SSH_AUTH_SOCK. See
	// SelectAgentKey.
	AgentKey string `json:"agent-key,omitempty"`
}

type nopCloser struct{}

func (nopCloser) Close() error { return nil }

// DefaultProfilePath is where a login is saved for this user.
func DefaultProfilePath() (string, error) {
	directory, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("%w: no user configuration directory", ErrLoginState)
	}
	return filepath.Join(directory, "wyrwood", "operator.json"), nil
}

// DefaultKeyPath is the generated key's path beside a profile.
func DefaultKeyPath(profilePath string) string {
	return filepath.Join(filepath.Dir(profilePath), "operator_key")
}

// LoadProfile reads a saved login.
func LoadProfile(path string) (Profile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Profile{}, fmt.Errorf("%w: read login", ErrLoginState)
	}
	var profile Profile
	if err := json.Unmarshal(data, &profile); err != nil || profile.URL == "" || profile.HostKey == "" {
		return Profile{}, fmt.Errorf("%w: parse login", ErrLoginState)
	}
	return profile, nil
}

// SaveProfile writes a login atomically with owner-only mode.
func SaveProfile(path string, profile Profile) error {
	encoded, err := json.MarshalIndent(profile, "", "  ")
	if err != nil {
		return fmt.Errorf("%w: encode login", ErrLoginState)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("%w: create login directory", ErrLoginState)
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".operator-*")
	if err != nil {
		return fmt.Errorf("%w: write login", ErrLoginState)
	}
	defer os.Remove(temporary.Name())
	_, writeErr := temporary.Write(append(encoded, '\n'))
	if err := errors.Join(writeErr, temporary.Close(), os.Rename(temporary.Name(), path)); err != nil {
		return fmt.Errorf("%w: write login", ErrLoginState)
	}
	return nil
}

// Signer loads the profile's key. The closer ends the SSH agent connection the
// signer uses; close it after the last request.
func (profile Profile) Signer() (ssh.Signer, io.Closer, error) {
	if profile.AgentKey == "" {
		signer, _, err := LoadOrCreateKey(profile.KeyFile)
		return signer, nopCloser{}, err
	}
	agent, connection, err := DialAgent(os.Getenv("SSH_AUTH_SOCK"))
	if err != nil {
		return nil, nil, err
	}
	signer, err := SelectAgentKey(agent, profile.AgentKey)
	if err != nil {
		_ = connection.Close()
		return nil, nil, err
	}
	return signer, connection, nil
}

// Dial connects with the saved login.
func (profile Profile) Dial(ctx context.Context) (*Client, error) {
	signer, closer, err := profile.Signer()
	if err != nil {
		return nil, err
	}
	client, err := Dial(ctx, Config{URL: profile.URL, Signer: signer, HostKey: profile.HostKey, Label: profile.Label})
	if err != nil {
		_ = closer.Close()
		return nil, err
	}
	client.onClose = closer
	return client, nil
}

// LoginOptions configure LoginProfile.
type LoginOptions struct {
	URL string
	// KeyFile is the key to use or generate. It defaults to DefaultKeyPath.
	KeyFile string
	// AgentKey selects one key of the SSH agent at SSH_AUTH_SOCK in place of a file.
	AgentKey string
	// Label is the name proposed for a pending key. A repeat login keeps the
	// saved one when this is empty.
	Label string
	// AcceptFingerprint is the exact host key to accept.
	AcceptFingerprint string
	// Accept decides on a host key when none is given or saved for this URL.
	Accept func(fingerprint string) bool
	// Announce receives the key's fingerprint before connecting.
	Announce func(fingerprint string)
}

// LoginProfile logs in and saves the login at path, also while the key is
// pending, so that the host key stays pinned and later commands can run once an
// operator approves the key. A saved login for the same URL keeps its key source
// and pin unless options replace them.
func LoginProfile(ctx context.Context, path string, options LoginOptions) (LoginResult, error) {
	saved, err := LoadProfile(path)
	if err != nil {
		if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
			return LoginResult{}, err
		}
		saved = Profile{}
	}
	profile := Profile{URL: options.URL, Label: options.Label, KeyFile: options.KeyFile, AgentKey: options.AgentKey, HostKey: options.AcceptFingerprint}
	if saved.URL == options.URL {
		if profile.HostKey == "" {
			profile.HostKey = saved.HostKey
		}
		if profile.Label == "" {
			profile.Label = saved.Label
		}
		if profile.KeyFile == "" && profile.AgentKey == "" {
			profile.KeyFile, profile.AgentKey = saved.KeyFile, saved.AgentKey
		}
	}
	if profile.KeyFile == "" && profile.AgentKey == "" {
		profile.KeyFile = DefaultKeyPath(path)
	}
	signer, closer, err := profile.Signer()
	if err != nil {
		return LoginResult{}, err
	}
	defer closer.Close()
	if options.Announce != nil {
		options.Announce(ssh.FingerprintSHA256(signer.PublicKey()))
	}
	result, err := Login(ctx, Config{URL: profile.URL, Signer: signer, HostKey: profile.HostKey, Label: profile.Label}, options.Accept)
	if err != nil {
		return result, err
	}
	profile.HostKey = result.HostKey
	return result, SaveProfile(path, profile)
}
