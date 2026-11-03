// ---
// relationships:
//   implements: operator-interface
//   uses: authenticate-operator-keys-over-ssh
// ---

package operator

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
)

// LoadOrCreateKey returns the key at path, generating it with owner-only mode
// when absent. created reports whether it was generated.
func LoadOrCreateKey(path string) (signer ssh.Signer, created bool, err error) {
	data, err := os.ReadFile(path)
	if err == nil {
		signer, err = ssh.ParsePrivateKey(data)
		if err != nil {
			return nil, false, fmt.Errorf("%w: parse key", ErrLoginState)
		}
		return signer, false, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, false, fmt.Errorf("%w: read key", ErrLoginState)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, false, fmt.Errorf("%w: create key directory", ErrLoginState)
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, false, fmt.Errorf("%w: generate key", ErrLoginState)
	}
	block, err := ssh.MarshalPrivateKey(private, "wyrwood operator")
	if err != nil {
		return nil, false, fmt.Errorf("%w: encode key", ErrLoginState)
	}
	// O_EXCL keeps a concurrent login's key: the loser reads the winner's.
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		signer, _, err = LoadOrCreateKey(path)
		return signer, false, err
	}
	if err != nil {
		return nil, false, fmt.Errorf("%w: write key", ErrLoginState)
	}
	_, writeErr := file.Write(pem.EncodeToMemory(block))
	if err := errors.Join(writeErr, file.Close()); err != nil {
		_ = os.Remove(path)
		return nil, false, fmt.Errorf("%w: write key", ErrLoginState)
	}
	signer, err = ssh.NewSignerFromKey(private)
	if err != nil {
		return nil, false, fmt.Errorf("%w: load key", ErrLoginState)
	}
	return signer, true, nil
}

// SelectAgentKey returns the one key of an SSH agent that selection names: its
// SHA256 fingerprint, its public key in authorized-keys form with or without
// the comment, or its comment. Only that key signs, and it is the only key a
// connection offers, so that no other key in the agent is recorded as pending.
func SelectAgentKey(agent sshagent.Agent, selection string) (ssh.Signer, error) {
	keys, err := agent.List()
	if err != nil {
		return nil, fmt.Errorf("%w: list keys", ErrKeySelection)
	}
	var wanted []byte
	if parsed, _, _, _, parseErr := ssh.ParseAuthorizedKey([]byte(selection)); parseErr == nil {
		wanted = parsed.Marshal()
	}
	var byKey, byName []*sshagent.Key
	for _, key := range keys {
		switch {
		case ssh.FingerprintSHA256(key) == selection, wanted != nil && bytes.Equal(key.Marshal(), wanted):
			byKey = append(byKey, key)
		case key.Comment == selection:
			byName = append(byName, key)
		}
	}
	matched := byKey
	if len(matched) == 0 {
		matched = byName
	}
	if len(matched) != 1 {
		return nil, fmt.Errorf("%w: %d keys match", ErrKeySelection, len(matched))
	}
	signers, err := agent.Signers()
	if err != nil {
		return nil, fmt.Errorf("%w: load signers", ErrKeySelection)
	}
	for _, signer := range signers {
		if bytes.Equal(signer.PublicKey().Marshal(), matched[0].Marshal()) {
			return signer, nil
		}
	}
	return nil, fmt.Errorf("%w: key is gone", ErrKeySelection)
}

// DialAgent connects to the SSH agent at socket. Close the returned closer when
// no signer from this agent is in use.
func DialAgent(socket string) (sshagent.Agent, net.Conn, error) {
	if socket == "" {
		return nil, nil, fmt.Errorf("%w: no SSH agent socket", ErrKeySelection)
	}
	connection, err := net.Dial("unix", socket)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: connect to SSH agent", ErrKeySelection)
	}
	return sshagent.NewClient(connection), connection, nil
}
