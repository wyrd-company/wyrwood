// ---
// relationships:
//   implements:
//     - agent
//     - ssh-agent-endpoint
// ---

package openbao

import (
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"strings"
	"time"

	"github.com/openbao/openbao/api/v2"
	"golang.org/x/crypto/ssh"
)

// UnwrapSecretID unwraps a response-wrapped AppRole secret identifier.
func UnwrapSecretID(ctx context.Context, client *api.Client, wrappingToken string) (string, error) {
	clone, err := withToken(client, "")
	if err != nil {
		return "", err
	}
	secret, err := clone.Logical().UnwrapWithContext(ctx, wrappingToken)
	if err != nil {
		return "", categorize(err)
	}
	if secret == nil {
		return "", &Error{Category: CategoryInvalid}
	}
	return requireString(secret.Data, "secret_id")
}

// RenewSelf renews token and returns the renewed lease.
func RenewSelf(ctx context.Context, client *api.Client, token Token) (Token, error) {
	clone, err := withToken(client, token.Value())
	if err != nil {
		return Token{}, err
	}
	secret, err := clone.Auth().Token().RenewSelfWithContext(ctx, int(token.TTL/time.Second))
	if err != nil {
		return Token{}, categorize(err)
	}
	renewed, err := tokenFromAuth(secret)
	if err != nil {
		return Token{}, err
	}
	return renewed, nil
}

// RevokeSelf revokes token.
func RevokeSelf(ctx context.Context, client *api.Client, token Token) error {
	clone, err := withToken(client, token.Value())
	if err != nil {
		return err
	}
	return categorize(clone.Auth().Token().RevokeSelfWithContext(ctx, ""))
}

// TransitPublicKey reads the latest public key of a Transit key with token.
func TransitPublicKey(ctx context.Context, client *api.Client, token Token, mount, name string) (TransitKey, error) {
	clone, err := withToken(client, token.Value())
	if err != nil {
		return TransitKey{}, err
	}
	key, err := ReadTransitKey(ctx, clone, mount, name)
	if err != nil {
		return TransitKey{}, err
	}
	if key.PublicKey == nil {
		return TransitKey{}, &Error{Category: CategoryInvalid}
	}
	return key, nil
}

// TransitSign signs data with a Transit key and returns the raw signature
// bytes. hash is sha2-256 or sha2-512 for RSA keys and ignored for ed25519.
func TransitSign(ctx context.Context, client *api.Client, token Token, mount, name, keyType, hash string, data []byte) ([]byte, error) {
	clone, err := withToken(client, token.Value())
	if err != nil {
		return nil, err
	}
	request := map[string]any{"input": base64.StdEncoding.EncodeToString(data)}
	path := mount + "/sign/" + name
	if strings.HasPrefix(keyType, "rsa-") {
		path += "/" + hash
		request["signature_algorithm"] = "pkcs1v15"
	}
	secret, err := clone.Logical().WriteWithContext(ctx, path, request)
	if err != nil {
		return nil, categorize(err)
	}
	if secret == nil {
		return nil, &Error{Category: CategoryInvalid}
	}
	encoded, err := requireString(secret.Data, "signature")
	if err != nil {
		return nil, err
	}
	parts := strings.Split(encoded, ":")
	if len(parts) != 3 || parts[0] != "vault" {
		return nil, &Error{Category: CategoryInvalid}
	}
	signature, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, &Error{Category: CategoryInvalid}
	}
	return signature, nil
}

// SignSSHKey asks an SSH-engine role to certify publicKey for principals and
// returns the parsed certificate.
func SignSSHKey(ctx context.Context, client *api.Client, token Token, mount, role string, publicKey ssh.PublicKey, principals []string) (*ssh.Certificate, error) {
	clone, err := withToken(client, token.Value())
	if err != nil {
		return nil, err
	}
	request := map[string]any{
		"public_key": string(ssh.MarshalAuthorizedKey(publicKey)),
		"cert_type":  "user",
	}
	if len(principals) > 0 {
		request["valid_principals"] = strings.Join(principals, ",")
	}
	secret, err := clone.Logical().WriteWithContext(ctx, mount+"/sign/"+role, request)
	if err != nil {
		return nil, categorize(err)
	}
	if secret == nil {
		return nil, &Error{Category: CategoryInvalid}
	}
	signed, err := requireString(secret.Data, "signed_key")
	if err != nil {
		return nil, err
	}
	parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(signed))
	if err != nil {
		return nil, &Error{Category: CategoryInvalid}
	}
	certificate, ok := parsed.(*ssh.Certificate)
	if !ok {
		return nil, &Error{Category: CategoryInvalid}
	}
	return certificate, nil
}

func parseTransitPublicKey(keyType, encoded string) (ssh.PublicKey, error) {
	switch {
	case keyType == "ed25519":
		raw, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, errors.New("invalid ed25519 public key")
		}
		return ssh.NewPublicKey(ed25519.PublicKey(raw))
	case strings.HasPrefix(keyType, "rsa-"):
		block, _ := pem.Decode([]byte(encoded))
		if block == nil {
			return nil, errors.New("invalid RSA public key")
		}
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rsaKey, ok := parsed.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("invalid RSA public key")
		}
		return ssh.NewPublicKey(rsaKey)
	}
	return nil, errors.New("unsupported Transit key type")
}
