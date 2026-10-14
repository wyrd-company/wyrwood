// ---
// relationships:
//   implements: agent-controller-protocol
// ---

package protocol

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
)

var (
	// ErrLineTooLong means a message line exceeded 1 MiB.
	ErrLineTooLong = errors.New("protocol line exceeds 1 MiB")
	// ErrInvalid means a line was not a valid protocol message.
	ErrInvalid = errors.New("invalid protocol message")
)

// Encode serializes one message as a single line including the newline.
func Encode(message Message) ([]byte, error) {
	if err := message.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	switch typed := message.(type) {
	case Inventory:
		if typed.Containers == nil {
			typed.Containers = []Container{}
		}
		message = typed
	case PolicySet:
		if typed.Bindings == nil {
			typed.Bindings = []Binding{}
		}
		message = typed
	}
	body, err := json.Marshal(message)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	header := fmt.Sprintf(`{"version":%d,"type":%q`, Version, message.MessageType())
	var line bytes.Buffer
	line.WriteString(header)
	if len(body) > 2 {
		line.WriteByte(',')
		line.Write(body[1 : len(body)-1])
	}
	line.WriteString("}\n")
	if line.Len() > MaximumLineBytes {
		return nil, ErrLineTooLong
	}
	return line.Bytes(), nil
}

// Decode parses one line, without its newline, into a validated message.
// Unknown fields are rejected.
func Decode(line []byte) (Message, error) {
	if len(line) >= MaximumLineBytes {
		return nil, ErrLineTooLong
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(line, &fields); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	var version int
	if raw, ok := fields["version"]; !ok || json.Unmarshal(raw, &version) != nil || version != Version || string(raw) != "1" {
		return nil, fmt.Errorf("%w: unsupported version", ErrInvalid)
	}
	var messageType Type
	if raw, ok := fields["type"]; !ok || json.Unmarshal(raw, &messageType) != nil {
		return nil, fmt.Errorf("%w: missing type", ErrInvalid)
	}
	delete(fields, "version")
	delete(fields, "type")
	var message Message
	switch messageType {
	case TypeHello:
		message = &Hello{}
	case TypeInventory:
		message = &Inventory{}
	case TypeContractResult:
		message = &ContractResult{}
	case TypeCredentialRequest:
		message = &CredentialRequest{}
	case TypePolicySet:
		message = &PolicySet{}
	case TypeCredential:
		message = &Credential{}
	case TypeRecreateRequest:
		message = &RecreateRequest{}
	case TypeUnbind:
		message = &Unbind{}
	default:
		return nil, fmt.Errorf("%w: unknown type", ErrInvalid)
	}
	body, err := json.Marshal(fields)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(message); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if err := requireFields(messageType, fields); err != nil {
		return nil, err
	}
	value := dereference(message)
	if err := value.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	return value, nil
}

var requiredFields = map[Type][]string{
	TypeHello:             {"agent-version", "allow-recreate"},
	TypeInventory:         {"containers"},
	TypeContractResult:    {"binding", "outcome"},
	TypeCredentialRequest: {"binding"},
	TypePolicySet:         {"openbao", "bindings"},
	TypeCredential:        {"binding", "approle-mount", "role-id", "wrapped-secret-id"},
	TypeRecreateRequest:   {"binding"},
	TypeUnbind:            {"binding"},
}

func requireFields(messageType Type, fields map[string]json.RawMessage) error {
	for _, name := range requiredFields[messageType] {
		if _, ok := fields[name]; !ok {
			return fmt.Errorf("%w: %s requires %s", ErrInvalid, messageType, name)
		}
	}
	return nil
}

func dereference(message Message) Message {
	switch typed := message.(type) {
	case *Hello:
		return *typed
	case *Inventory:
		if typed.Containers == nil {
			typed.Containers = []Container{}
		}
		return *typed
	case *ContractResult:
		return *typed
	case *CredentialRequest:
		return *typed
	case *PolicySet:
		if typed.Bindings == nil {
			typed.Bindings = []Binding{}
		}
		return *typed
	case *Credential:
		return *typed
	case *RecreateRequest:
		return *typed
	case *Unbind:
		return *typed
	}
	return message
}

// Conn reads and writes protocol messages over one stream. Writes are
// serialized; reads must come from one goroutine.
type Conn struct {
	reader *bufio.Reader
	mu     sync.Mutex
	writer io.Writer
}

// NewConn wraps a bidirectional stream.
func NewConn(stream io.ReadWriter) *Conn {
	return &Conn{reader: bufio.NewReaderSize(stream, 64<<10), writer: stream}
}

// Send writes one message.
func (conn *Conn) Send(message Message) error {
	line, err := Encode(message)
	if err != nil {
		return err
	}
	conn.mu.Lock()
	defer conn.mu.Unlock()
	_, err = conn.writer.Write(line)
	return err
}

// Receive reads one message. An oversize line returns ErrLineTooLong and the
// connection must be closed.
func (conn *Conn) Receive() (Message, error) {
	var line []byte
	for {
		fragment, err := conn.reader.ReadSlice('\n')
		if len(line)+len(fragment) > MaximumLineBytes {
			return nil, ErrLineTooLong
		}
		line = append(line, fragment...)
		if err == nil {
			break
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if errors.Is(err, io.EOF) && len(line) > 0 {
			return nil, io.ErrUnexpectedEOF
		}
		return nil, err
	}
	return Decode(line[:len(line)-1])
}
