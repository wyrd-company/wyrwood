// ---
// relationships:
//   implements: agent
//   uses: enroll-agents-with-host-generated-keys
// ---

// Package agent composes the Wyrwood agent: login and identity, engine
// observation, the controller session, credentials, consumer directories,
// contract enforcement, endpoints, the control socket, and events.
package agent

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"

	"golang.org/x/crypto/ssh"
)

// Paths locate the agent's configuration, durable state, and runtime files.
type Paths struct {
	Config  string
	State   string
	Runtime string
}

// DefaultPaths are the system service locations.
func DefaultPaths() Paths {
	return Paths{Config: "/etc/wyrwood/agent.yml", State: "/var/lib/wyrwood", Runtime: "/run/wyrwood"}
}

// AgentKey is the agent's private key.
func (paths Paths) AgentKey() string { return filepath.Join(paths.State, "agent_key") }

// KnownController records the accepted controller URL and host-key fingerprint.
func (paths Paths) KnownController() string { return filepath.Join(paths.State, "controller.json") }

// PolicyCache is the cached policy set.
func (paths Paths) PolicyCache() string { return filepath.Join(paths.State, "policy-cache.json") }

// Events is the agent event store.
func (paths Paths) Events() string { return filepath.Join(paths.State, "events", "agent.events") }

// ControlSocket is the owner-only control socket.
func (paths Paths) ControlSocket() string { return filepath.Join(paths.Runtime, "control.sock") }

// ServiceUser is the system user the agent runs as.
const ServiceUser = "wyrwood"

// LoadOrCreateKey returns the agent key, generating it with owner-only mode
// when absent. created reports whether it was generated.
func LoadOrCreateKey(paths Paths) (signer ssh.Signer, created bool, err error) {
	data, err := os.ReadFile(paths.AgentKey())
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(paths.State, 0o700); err != nil {
			return nil, false, err
		}
		_, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, false, err
		}
		block, err := ssh.MarshalPrivateKey(private, "wyrwood agent")
		if err != nil {
			return nil, false, err
		}
		data = pem.EncodeToMemory(block)
		if err := writeOwnerOnly(paths.AgentKey(), data, true); err != nil {
			return nil, false, err
		}
		created = true
	} else if err != nil {
		return nil, false, err
	}
	signer, err = ssh.ParsePrivateKey(data)
	if err != nil {
		return nil, false, errors.New("agent key is not a valid private key")
	}
	return signer, created, nil
}

// LoadKey returns the existing agent key.
func LoadKey(paths Paths) (ssh.Signer, error) {
	data, err := os.ReadFile(paths.AgentKey())
	if err != nil {
		return nil, err
	}
	signer, err := ssh.ParsePrivateKey(data)
	if err != nil {
		return nil, errors.New("agent key is not a valid private key")
	}
	return signer, nil
}

// KnownControllerRecord is the accepted controller identity.
type KnownControllerRecord struct {
	URL         string `json:"url"`
	Fingerprint string `json:"fingerprint"`
}

// LoadKnownController returns the accepted controller identity.
func LoadKnownController(paths Paths) (KnownControllerRecord, error) {
	data, err := os.ReadFile(paths.KnownController())
	if err != nil {
		return KnownControllerRecord{}, err
	}
	var record KnownControllerRecord
	if err := json.Unmarshal(data, &record); err != nil || record.URL == "" || record.Fingerprint == "" {
		return KnownControllerRecord{}, errors.New("known controller record is invalid")
	}
	return record, nil
}

// SaveKnownController records the accepted controller identity.
func SaveKnownController(paths Paths, record KnownControllerRecord) error {
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return writeOwnerOnly(paths.KnownController(), append(data, '\n'), false)
}

func writeOwnerOnly(path string, data []byte, exclusive bool) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".wyrwood-*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if exclusive {
		if err := os.Link(name, path); err != nil {
			return fmt.Errorf("publish %s: %w", filepath.Base(path), err)
		}
		return nil
	}
	return os.Rename(name, path)
}

// handOver gives the agent's durable files to the service user when login
// runs as root, so the daemon can read them.
func handOver(paths Paths) {
	if os.Geteuid() != 0 {
		return
	}
	account, err := user.Lookup(ServiceUser)
	if err != nil {
		return
	}
	uid, uidErr := strconv.Atoi(account.Uid)
	gid, gidErr := strconv.Atoi(account.Gid)
	if uidErr != nil || gidErr != nil {
		return
	}
	for _, path := range []string{paths.State, paths.AgentKey(), paths.KnownController()} {
		_ = os.Lchown(path, uid, gid)
	}
}
