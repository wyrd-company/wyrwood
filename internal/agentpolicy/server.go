// ---
// relationships:
//   implements: linux-per-user-agent-proxy
// ---

package agentpolicy

import (
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

const (
	requestIdentities = 11
	signRequest       = 13
	extensionRequest  = 27

	agentFailure          = 5
	agentExtensionFailure = 28

	// OpenSSH portable ssh-agent.c defines AGENT_MAX_LEN as 256 KiB.
	maxMessageBytes = 256 * 1024
)

// Serve runs the bounded, deny-by-default SSH-agent protocol for one
// downstream connection. It performs no logging and never returns request or
// upstream-operation contents in an error.
func Serve(policyAgent *Agent, connection io.ReadWriter) error {
	if policyAgent == nil {
		return errors.New("policy agent is required")
	}
	if connection == nil {
		return errors.New("connection is required")
	}

	var sizeBuffer [4]byte
	for {
		if _, err := io.ReadFull(connection, sizeBuffer[:]); err != nil {
			return err
		}
		size := binary.BigEndian.Uint32(sizeBuffer[:])
		if size == 0 {
			return errors.New("agent request is empty")
		}
		if size > maxMessageBytes {
			return errors.New("agent request exceeds size limit")
		}

		request := make([]byte, size)
		if _, err := io.ReadFull(connection, request); err != nil {
			return err
		}
		response := processRequest(policyAgent, request)
		if len(response) > maxMessageBytes {
			response = []byte{agentFailure}
		}
		binary.BigEndian.PutUint32(sizeBuffer[:], uint32(len(response)))
		if err := writeAll(connection, sizeBuffer[:]); err != nil {
			return err
		}
		if err := writeAll(connection, response); err != nil {
			return err
		}
	}
}

func processRequest(policyAgent *Agent, request []byte) []byte {
	switch request[0] {
	case requestIdentities:
		return processIdentities(policyAgent, request)
	case signRequest:
		return processSign(policyAgent, request)
	case extensionRequest:
		return processExtension(policyAgent, request)
	default:
		// Reject mutations, legacy operations, smartcard operations, and all
		// unknown opcodes before parsing their potentially sensitive payloads.
		return []byte{agentFailure}
	}
}

func processIdentities(policyAgent *Agent, request []byte) []byte {
	var decoded struct {
		Rest []byte `sshtype:"11" ssh:"rest"`
	}
	if ssh.Unmarshal(request, &decoded) != nil || len(decoded.Rest) != 0 {
		return []byte{agentFailure}
	}
	keys, err := policyAgent.List()
	if err != nil {
		return []byte{agentFailure}
	}

	var encodedKeys []byte
	for _, key := range keys {
		if key == nil {
			return []byte{agentFailure}
		}
		encodedKeys = append(encodedKeys, ssh.Marshal(struct {
			Blob    []byte
			Comment string
		}{Blob: key.Marshal(), Comment: key.Comment})...)
		if len(encodedKeys) > maxMessageBytes {
			return []byte{agentFailure}
		}
	}
	return ssh.Marshal(struct {
		NumKeys uint32 `sshtype:"12"`
		Keys    []byte `ssh:"rest"`
	}{NumKeys: uint32(len(keys)), Keys: encodedKeys})
}

func processSign(policyAgent *Agent, request []byte) []byte {
	var decoded struct {
		KeyBlob []byte `sshtype:"13"`
		Data    []byte
		Flags   uint32
	}
	if ssh.Unmarshal(request, &decoded) != nil {
		return []byte{agentFailure}
	}
	key, err := ssh.ParsePublicKey(decoded.KeyBlob)
	if err != nil {
		return []byte{agentFailure}
	}
	signature, err := policyAgent.SignWithFlags(key, decoded.Data, agent.SignatureFlags(decoded.Flags))
	if err != nil || signature == nil {
		return []byte{agentFailure}
	}
	return ssh.Marshal(struct {
		Signature []byte `sshtype:"14"`
	}{Signature: ssh.Marshal(signature)})
}

func processExtension(policyAgent *Agent, request []byte) []byte {
	var decoded struct {
		Extension string `sshtype:"27"`
		Contents  []byte `ssh:"rest"`
	}
	if ssh.Unmarshal(request, &decoded) != nil {
		return []byte{agentFailure}
	}
	response, err := policyAgent.Extension(decoded.Extension, decoded.Contents)
	if errors.Is(err, agent.ErrExtensionUnsupported) {
		return []byte{agentFailure}
	}
	if err != nil {
		return []byte{agentExtensionFailure}
	}
	if len(response) == 0 {
		// ExtendedAgent.Extension returns the complete response, including its
		// type byte. An empty success violates that contract.
		return []byte{agentExtensionFailure}
	}
	return response
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		written, err := writer.Write(data)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		data = data[written:]
	}
	return nil
}
