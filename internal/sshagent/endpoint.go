// ---
// relationships:
//   implements: ssh-agent-endpoint
//   uses: make-openbao-the-secret-and-key-authority
// ---

// Package sshagent serves a standard SSH-agent socket whose identities are
// OpenBao Transit keys and SSH-engine certificates named by the container's
// policy. Private keys never leave OpenBao, except the per-container
// certificate key, which exists only in agent memory.
package sshagent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"

	"github.com/wyrd-company/wyrwood/internal/binding"
	"github.com/wyrd-company/wyrwood/internal/events"
	"github.com/wyrd-company/wyrwood/internal/openbao"
)

var (
	errRefused     = errors.New("operation refused")
	errNotBound    = errors.New("not bound")
	errNoToken     = errors.New("no token")
	errUnknownKey  = errors.New("identity not offered")
	errUnsupported = errors.New("unsupported signature algorithm")
)

// Endpoint serves ssh-agent sockets.
type Endpoint struct {
	Timeout time.Duration
	Now     func() time.Time
}

// New returns an endpoint with the given OpenBao operation timeout.
func New(timeout time.Duration) *Endpoint { return &Endpoint{Timeout: timeout, Now: time.Now} }

// Serve serves one consumer's ssh-agent socket until the listener closes.
// Certificates and their keys live for as long as the socket.
func (endpoint *Endpoint) Serve(listener net.Listener, lookup binding.Lookup, record binding.Recorder) {
	certificates := &certificateCache{entries: map[string]*certificate{}}
	stop := make(chan struct{})
	defer close(stop)
	go endpoint.refresh(stop, certificates, lookup, record)
	for {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		go func() {
			defer connection.Close()
			session := &session{endpoint: endpoint, lookup: lookup, record: record, certificates: certificates}
			_ = sshagent.ServeAgent(session, connection)
		}()
	}
}

// refresh reissues certificates before a third of their validity remains,
// so clients never see a gap.
func (endpoint *Endpoint) refresh(stop <-chan struct{}, certificates *certificateCache, lookup binding.Lookup, record binding.Recorder) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			view, ok := lookup()
			if !ok || !view.HasToken {
				continue
			}
			for _, role := range view.Policy.CARoles() {
				if entry := certificates.get(view.ID, role); entry != nil && entry.needsReissue(endpoint.Now()) {
					_, _ = endpoint.issue(view, role, certificates, record)
				}
			}
		}
	}
}

type certificate struct {
	signer      ssh.Signer
	certificate *ssh.Certificate
}

func (entry *certificate) needsReissue(now time.Time) bool {
	validAfter := time.Unix(int64(entry.certificate.ValidAfter), 0)
	validBefore := time.Unix(int64(entry.certificate.ValidBefore), 0)
	return now.After(validBefore.Add(-validBefore.Sub(validAfter) / 3))
}

type certificateCache struct {
	mu      sync.Mutex
	entries map[string]*certificate
	keys    map[string]ed25519.PrivateKey
}

func cacheKey(bindingID, role string) string { return bindingID + "\x00" + role }

func (cache *certificateCache) get(bindingID, role string) *certificate {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	return cache.entries[cacheKey(bindingID, role)]
}

// key returns the in-memory key pair for a binding and role, generating it
// on first use.
func (cache *certificateCache) key(bindingID, role string) (ed25519.PrivateKey, error) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if cache.keys == nil {
		cache.keys = map[string]ed25519.PrivateKey{}
	}
	if private, ok := cache.keys[cacheKey(bindingID, role)]; ok {
		return private, nil
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	cache.keys[cacheKey(bindingID, role)] = private
	return private, nil
}

func (cache *certificateCache) put(bindingID, role string, entry *certificate) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	cache.entries[cacheKey(bindingID, role)] = entry
}

// issue requests a certificate for the binding's key from an SSH-engine role.
func (endpoint *Endpoint) issue(view binding.View, role string, certificates *certificateCache, record binding.Recorder) (*certificate, error) {
	started := endpoint.Now()
	private, err := certificates.key(view.ID, role)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), endpoint.Timeout)
	defer cancel()
	issued, err := openbao.SignSSHKey(ctx, view.Client, view.Token, view.Mounts.SSH, role, signer.PublicKey(), nil)
	fingerprint := ssh.FingerprintSHA256(signer.PublicKey())
	recordOutcome(record, events.OperationSSHCertificate, view, fingerprint, started, endpoint.Now(), err)
	if err != nil {
		return nil, err
	}
	entry := &certificate{signer: signer, certificate: issued}
	certificates.put(view.ID, role, entry)
	return entry, nil
}

// session is one ssh-agent connection.
type session struct {
	endpoint     *Endpoint
	lookup       binding.Lookup
	record       binding.Recorder
	certificates *certificateCache
	// Retain the forwarding fact for this connection without storing bind payloads.
	forwarded bool
}

type identity struct {
	key            *sshagent.Key
	transit        *openbao.TransitKey
	certificate    *certificate
	notForwardable bool
}

func (session *session) current() (binding.View, error) {
	view, ok := session.lookup()
	if !ok {
		return binding.View{}, errNotBound
	}
	if !view.HasToken || view.Client == nil {
		return view, errNoToken
	}
	return view, nil
}

// identities resolves every identity the current policy offers.
func (session *session) identities(view binding.View) ([]identity, error) {
	endpoint := session.endpoint
	var result []identity
	var firstErr error
	var restrictedKeys, restrictedRoles []string
	if view.Policy.SSH != nil && view.Policy.SSH.NotForwardable != nil {
		restrictedKeys = view.Policy.SSH.NotForwardable.TransitKeys
		restrictedRoles = view.Policy.SSH.NotForwardable.CARoles
	}
	for _, name := range view.Policy.TransitKeys() {
		ctx, cancel := context.WithTimeout(context.Background(), endpoint.Timeout)
		key, err := openbao.TransitPublicKey(ctx, view.Client, view.Token, view.Mounts.Transit, name)
		cancel()
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		transit := key
		result = append(result, identity{
			key:            &sshagent.Key{Format: key.PublicKey.Type(), Blob: key.PublicKey.Marshal(), Comment: name},
			transit:        &transit,
			notForwardable: slices.Contains(restrictedKeys, name),
		})
	}
	for _, role := range view.Policy.CARoles() {
		entry := session.certificates.get(view.ID, role)
		if entry == nil || entry.needsReissue(endpoint.Now()) {
			issued, err := endpoint.issue(view, role, session.certificates, session.record)
			if err != nil {
				if entry == nil {
					if firstErr == nil {
						firstErr = err
					}
					continue
				}
			} else {
				entry = issued
			}
		}
		result = append(result, identity{
			key:            &sshagent.Key{Format: entry.certificate.Type(), Blob: entry.certificate.Marshal(), Comment: role},
			certificate:    entry,
			notForwardable: slices.Contains(restrictedRoles, role),
		})
	}
	if len(result) == 0 && firstErr != nil {
		return nil, firstErr
	}
	return result, nil
}

// List returns the identities the container's current policy offers.
func (session *session) List() ([]*sshagent.Key, error) {
	started := session.endpoint.Now()
	view, err := session.current()
	if err != nil {
		recordOutcome(session.record, events.OperationSSHList, view, "", started, session.endpoint.Now(), err)
		if errors.Is(err, errNotBound) || errors.Is(err, errNoToken) {
			return []*sshagent.Key{}, nil
		}
		return nil, err
	}
	resolved, err := session.identities(view)
	recordOutcome(session.record, events.OperationSSHList, view, "", started, session.endpoint.Now(), err)
	if err != nil {
		return nil, err
	}
	keys := make([]*sshagent.Key, 0, len(resolved))
	for _, item := range resolved {
		keys = append(keys, item.key)
	}
	return keys, nil
}

// Sign signs with the default algorithm for the key type.
func (session *session) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return session.SignWithFlags(key, data, 0)
}

// SignWithFlags signs data with the identity matching key, consulting the
// current policy so a removed identity is refused immediately.
func (session *session) SignWithFlags(key ssh.PublicKey, data []byte, flags sshagent.SignatureFlags) (*ssh.Signature, error) {
	started := session.endpoint.Now()
	fingerprint := ssh.FingerprintSHA256(key)
	view, err := session.current()
	if err != nil {
		recordOutcome(session.record, events.OperationSSHSign, view, fingerprint, started, session.endpoint.Now(), err)
		return nil, err
	}
	resolved, err := session.identities(view)
	if err != nil {
		recordOutcome(session.record, events.OperationSSHSign, view, fingerprint, started, session.endpoint.Now(), err)
		return nil, err
	}
	blob := key.Marshal()
	for _, item := range resolved {
		if !bytes.Equal(item.key.Blob, blob) {
			continue
		}
		if session.forwarded && item.notForwardable {
			recordOutcome(session.record, events.OperationSSHSign, view, fingerprint, started, session.endpoint.Now(), errRefused)
			return nil, errRefused
		}
		var signature *ssh.Signature
		if item.transit != nil {
			signature, err = session.signTransit(view, *item.transit, data, flags)
		} else {
			signature, err = signCertificate(item.certificate.signer, data, flags)
		}
		recordOutcome(session.record, events.OperationSSHSign, view, fingerprint, started, session.endpoint.Now(), err)
		return signature, err
	}
	recordOutcome(session.record, events.OperationSSHSign, view, fingerprint, started, session.endpoint.Now(), errUnknownKey)
	return nil, errUnknownKey
}

func (session *session) signTransit(view binding.View, key openbao.TransitKey, data []byte, flags sshagent.SignatureFlags) (*ssh.Signature, error) {
	format, hash := ssh.KeyAlgoED25519, ""
	if strings.HasPrefix(key.Type, "rsa-") {
		switch {
		case flags&sshagent.SignatureFlagRsaSha512 != 0:
			format, hash = ssh.KeyAlgoRSASHA512, "sha2-512"
		case flags&sshagent.SignatureFlagRsaSha256 != 0:
			format, hash = ssh.KeyAlgoRSASHA256, "sha2-256"
		default:
			// SHA-1 ssh-rsa signatures are not offered.
			return nil, errUnsupported
		}
	} else if key.Type != "ed25519" {
		return nil, errUnsupported
	}
	ctx, cancel := context.WithTimeout(context.Background(), session.endpoint.Timeout)
	defer cancel()
	raw, err := openbao.TransitSign(ctx, view.Client, view.Token, view.Mounts.Transit, key.Name, key.Type, hash, data)
	if err != nil {
		return nil, err
	}
	signature := &ssh.Signature{Format: format, Blob: raw}
	if err := key.PublicKey.Verify(data, signature); err != nil {
		return nil, errors.New("OpenBao returned a signature that does not verify")
	}
	return signature, nil
}

func signCertificate(signer ssh.Signer, data []byte, flags sshagent.SignatureFlags) (*ssh.Signature, error) {
	if flags&(sshagent.SignatureFlagRsaSha256|sshagent.SignatureFlagRsaSha512) != 0 {
		return nil, errUnsupported
	}
	return signer.Sign(rand.Reader, data)
}

// Extension accepts session-bind@openssh.com and denies every other
// extension. Verified binds record an event and retain whether forwarding
// occurred on this connection, so later non-forwarding binds cannot clear it.
func (session *session) Extension(extensionType string, contents []byte) ([]byte, error) {
	if extensionType != "session-bind@openssh.com" {
		return nil, sshagent.ErrExtensionUnsupported
	}
	started := session.endpoint.Now()
	view, _ := session.lookup()
	var message struct {
		HostKey    []byte
		SessionID  []byte
		Signature  []byte
		Forwarding bool
	}
	if err := ssh.Unmarshal(contents, &message); err != nil {
		recordOutcome(session.record, events.OperationSSHSessionBind, view, "", started, session.endpoint.Now(), errRefused)
		return nil, errRefused
	}
	hostKey, err := ssh.ParsePublicKey(message.HostKey)
	if err == nil {
		var signature ssh.Signature
		if err = ssh.Unmarshal(message.Signature, &signature); err == nil {
			err = hostKey.Verify(message.SessionID, &signature)
		}
	}
	if err != nil {
		recordOutcome(session.record, events.OperationSSHSessionBind, view, "", started, session.endpoint.Now(), errRefused)
		return nil, errRefused
	}
	session.forwarded = session.forwarded || message.Forwarding
	recordOutcome(session.record, events.OperationSSHSessionBind, view, "", started, session.endpoint.Now(), nil)
	return nil, nil
}

// Administration requests are refused: identities come only from policy.
func (session *session) Add(sshagent.AddedKey) error    { return errRefused }
func (session *session) Remove(ssh.PublicKey) error     { return errRefused }
func (session *session) RemoveAll() error               { return errRefused }
func (session *session) Lock([]byte) error              { return errRefused }
func (session *session) Unlock([]byte) error            { return errRefused }
func (session *session) Signers() ([]ssh.Signer, error) { return nil, errRefused }

func recordOutcome(record binding.Recorder, operation events.Operation, view binding.View, fingerprint string, started, finished time.Time, err error) {
	if record == nil {
		return
	}
	outcome, code := events.OutcomeOK, events.ErrorNone
	switch {
	case err == nil:
	case errors.Is(err, errNotBound):
		outcome, code = events.OutcomeDenied, events.ErrorNotBound
	case errors.Is(err, errNoToken):
		outcome, code = events.OutcomeFailed, events.ErrorNoToken
	case errors.Is(err, errUnknownKey), errors.Is(err, errUnsupported), errors.Is(err, errRefused):
		outcome, code = events.OutcomeDenied, events.ErrorPolicyDenied
	default:
		switch openbao.CategoryOf(err) {
		case openbao.CategoryDenied, openbao.CategoryInvalid, openbao.CategoryNotFound:
			outcome, code = events.OutcomeDenied, events.ErrorOpenBaoDenied
		case openbao.CategoryTimeout:
			outcome, code = events.OutcomeTimeout, events.ErrorOpenBaoTimeout
		default:
			outcome, code = events.OutcomeFailed, events.ErrorOpenBaoUnavailable
		}
	}
	record(events.Event{
		Time: finished.UTC(), Operation: operation, Outcome: outcome, ErrorCode: code, Latency: finished.Sub(started),
		Binding: view.ID, ContainerKey: view.ContainerKey, Fingerprint: fingerprint,
	})
}
