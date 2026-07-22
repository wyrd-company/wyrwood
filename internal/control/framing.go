//go:build linux

// ---
// relationships:
//   implements: control-interface
// ---

package control

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

var errEncodedFrameTooLarge = errors.New("encoded control frame exceeds the supported bound")

func readJSONFrame(reader io.Reader, maximum uint32, destination any) error {
	var length uint32
	if err := binary.Read(reader, binary.BigEndian, &length); err != nil {
		return errors.New("read control frame header")
	}
	if length == 0 || length > maximum {
		return errors.New("control frame length is outside the supported bound")
	}
	data := make([]byte, length)
	if _, err := io.ReadFull(reader, data); err != nil {
		return errors.New("read control frame body")
	}
	if err := rejectDuplicateObjectFields(data); err != nil {
		return errors.New("decode control frame")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return errors.New("decode control frame")
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("control frame must contain one JSON value")
	}
	return nil
}

func rejectDuplicateObjectFields(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	var parse func(int) error
	parse = func(depth int) error {
		if depth > 64 {
			return errors.New("JSON nesting exceeds the supported bound")
		}
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				field, err := decoder.Token()
				if err != nil {
					return err
				}
				name, ok := field.(string)
				if !ok {
					return errors.New("JSON object field is not a string")
				}
				if _, exists := seen[name]; exists {
					return errors.New("JSON object field is duplicated")
				}
				seen[name] = struct{}{}
				if err := parse(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for decoder.More() {
				if err := parse(depth + 1); err != nil {
					return err
				}
			}
		default:
			return errors.New("unsupported JSON delimiter")
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		expected := json.Delim('}')
		if delimiter == '[' {
			expected = ']'
		}
		if closing != expected {
			return errors.New("JSON delimiter mismatch")
		}
		return nil
	}
	if err := parse(0); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("control frame must contain one JSON value")
	}
	return nil
}

func writeJSONFrame(writer io.Writer, maximum uint32, value any) error {
	frame, err := encodeJSONFrame(maximum, value)
	if err != nil {
		return err
	}
	return writeEncodedFrame(writer, frame)
}

func encodeJSONFrame(maximum uint32, value any) ([]byte, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("encode control frame: %w", err)
	}
	if len(data) == 0 || len(data) > int(maximum) {
		return nil, errEncodedFrameTooLarge
	}
	frame := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(data)))
	copy(frame[4:], data)
	return frame, nil
}

func writeEncodedFrame(writer io.Writer, frame []byte) error {
	for len(frame) > 0 {
		written, err := writer.Write(frame)
		if written < 0 || written > len(frame) {
			return errors.New("control frame writer returned an invalid count")
		}
		frame = frame[written:]
		if err != nil {
			return errors.New("write control frame")
		}
		if written == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func validateRequest(request Request) ErrorCode {
	if request.Version != Version {
		return ErrorUnsupportedVersion
	}
	switch request.Operation {
	case OperationApply, OperationKeys, OperationStatus:
		if requestHasFields(request) {
			return ErrorBadRequest
		}
	case OperationEvents:
		if request.Limit == nil || *request.Limit < 1 || *request.Limit > MaximumEventLimit || requestHasOtherFields(request, "limit") {
			return ErrorBadRequest
		}
	case OperationConfiguration:
		if request.Offset == nil || request.Limit == nil || *request.Offset < 0 || *request.Limit < 1 || *request.Limit > MaximumConfigurationPageSize ||
			requestHasOtherFields(request, "offset", "limit", "expected_revision") {
			return ErrorBadRequest
		}
		if *request.Offset == 0 && request.ExpectedRevision != nil || *request.Offset > 0 && !validRevisionPointer(request.ExpectedRevision) {
			return ErrorBadRequest
		}
	case OperationSetUpstream:
		if !validRevisionPointer(request.ExpectedRevision) || request.Upstream == nil || !validWirePath(*request.Upstream) ||
			requestHasOtherFields(request, "expected_revision", "upstream") {
			return ErrorBadRequest
		}
	case OperationSetTimeouts:
		if !validRevisionPointer(request.ExpectedRevision) || request.Timeouts == nil || !validWireTimeouts(*request.Timeouts) ||
			requestHasOtherFields(request, "expected_revision", "timeouts") {
			return ErrorBadRequest
		}
	case OperationPutConsumer:
		if !validRevisionPointer(request.ExpectedRevision) || request.Consumer == nil || !validWireConsumer(*request.Consumer) ||
			request.ConsumerID != nil && !validRevision(*request.ConsumerID) ||
			requestHasOtherFields(request, "expected_revision", "consumer_id", "consumer") {
			return ErrorBadRequest
		}
	case OperationRetireConsumer:
		if !validRevisionPointer(request.ExpectedRevision) || !validRevisionPointer(request.ConsumerID) ||
			requestHasOtherFields(request, "expected_revision", "consumer_id") {
			return ErrorBadRequest
		}
	default:
		return ErrorBadRequest
	}
	return ErrorNone
}

func requestHasFields(request Request) bool {
	return request.Limit != nil || request.Offset != nil || request.ExpectedRevision != nil || request.Upstream != nil ||
		request.Timeouts != nil || request.ConsumerID != nil || request.Consumer != nil
}

func requestHasOtherFields(request Request, allowed ...string) bool {
	set := make(map[string]bool, len(allowed))
	for _, field := range allowed {
		set[field] = true
	}
	return request.Limit != nil && !set["limit"] || request.Offset != nil && !set["offset"] ||
		request.ExpectedRevision != nil && !set["expected_revision"] || request.Upstream != nil && !set["upstream"] ||
		request.Timeouts != nil && !set["timeouts"] || request.ConsumerID != nil && !set["consumer_id"] ||
		request.Consumer != nil && !set["consumer"]
}
