// ---
// relationships:
//   implements: operational-events
// ---

package events

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"time"
)

const (
	fileMagic             = "WYREVT02"
	frameHeaderBytes      = 8
	maximumEventJSONBytes = 2048
)

var checksumTable = crc32.MakeTable(crc32.Castagnoli)

// Record is the closed JSON projection of one event, matching the
// operational-event schema field for field.
type Record struct {
	Time         string    `json:"time"`
	Operation    Operation `json:"operation"`
	Outcome      Outcome   `json:"outcome"`
	LatencyNS    int64     `json:"latency-ns"`
	Error        ErrorCode `json:"error,omitempty"`
	Agent        string    `json:"agent,omitempty"`
	Binding      string    `json:"binding,omitempty"`
	ContainerKey string    `json:"container-key,omitempty"`
	Policy       string    `json:"policy,omitempty"`
	Operator     string    `json:"operator,omitempty"`
	Fingerprint  string    `json:"fingerprint,omitempty"`
	Mount        Mount     `json:"mount,omitempty"`
	Method       Method    `json:"method,omitempty"`
}

// Record projects a validated event into its schema record.
func (event Event) Record() Record {
	return Record{
		Time:         event.Time.UTC().Format(time.RFC3339Nano),
		Operation:    event.Operation,
		Outcome:      event.Outcome,
		LatencyNS:    int64(event.Latency),
		Error:        event.ErrorCode,
		Agent:        event.Agent,
		Binding:      event.Binding,
		ContainerKey: event.ContainerKey,
		Policy:       event.Policy,
		Operator:     event.Operator,
		Fingerprint:  event.Fingerprint,
		Mount:        event.Mount,
		Method:       event.Method,
	}
}

// Event converts a schema record back into a validated event.
func (record Record) Event() (Event, error) {
	timestamp, err := time.Parse(time.RFC3339Nano, record.Time)
	if err != nil {
		return Event{}, fmt.Errorf("decode event time: %w", err)
	}
	if record.LatencyNS < 0 {
		return Event{}, fmt.Errorf("decode event: negative latency")
	}
	event := Event{
		Time:         timestamp,
		Operation:    record.Operation,
		Outcome:      record.Outcome,
		Latency:      time.Duration(record.LatencyNS),
		ErrorCode:    record.Error,
		Agent:        record.Agent,
		Binding:      record.Binding,
		ContainerKey: record.ContainerKey,
		Policy:       record.Policy,
		Operator:     record.Operator,
		Fingerprint:  record.Fingerprint,
		Mount:        record.Mount,
		Method:       record.Method,
	}
	if err := event.Validate(); err != nil {
		return Event{}, fmt.Errorf("validate event: %w", err)
	}
	return event, nil
}

func encodeFrame(event Event) ([]byte, error) {
	if err := event.Validate(); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(event.Record())
	if err != nil {
		return nil, fmt.Errorf("encode event: %w", err)
	}
	if len(payload) > maximumEventJSONBytes {
		return nil, fmt.Errorf("encoded event exceeds %d bytes", maximumEventJSONBytes)
	}
	frame := make([]byte, frameHeaderBytes+len(payload))
	binary.BigEndian.PutUint32(frame[0:4], uint32(len(payload)))
	binary.BigEndian.PutUint32(frame[4:8], crc32.Checksum(payload, checksumTable))
	copy(frame[frameHeaderBytes:], payload)
	return frame, nil
}

func decodeFrame(payload []byte) (Event, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(payload, &fields); err != nil {
		return Event{}, fmt.Errorf("decode event object: %w", err)
	}
	for _, required := range []string{"time", "operation", "outcome", "latency-ns"} {
		if _, exists := fields[required]; !exists {
			return Event{}, fmt.Errorf("decode event: required property %q is absent", required)
		}
	}

	var record Record
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return Event{}, fmt.Errorf("decode event: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return Event{}, fmt.Errorf("decode event: trailing JSON value")
		}
		return Event{}, fmt.Errorf("decode event trailer: %w", err)
	}
	return record.Event()
}

// loadFrames returns the valid events and an optional truncation offset. Only
// an interrupted final header/body or a checksum-invalid final frame is a
// recoverable crash tail. Any corruption before the final frame is fatal.
func loadFrames(file *os.File) ([]Event, int64, error) {
	info, err := file.Stat()
	if err != nil {
		return nil, -1, fmt.Errorf("inspect event store: %w", err)
	}
	if info.Size() == 0 {
		return nil, -1, nil
	}
	if info.Size() < int64(len(fileMagic)) {
		return nil, -1, fmt.Errorf("%w: incomplete file header", ErrCorrupt)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, -1, fmt.Errorf("seek event store: %w", err)
	}
	header := make([]byte, len(fileMagic))
	if _, err := io.ReadFull(file, header); err != nil {
		return nil, -1, fmt.Errorf("read event store header: %w", err)
	}
	if string(header) != fileMagic {
		return nil, -1, fmt.Errorf("%w: unsupported file header", ErrCorrupt)
	}

	events := make([]Event, 0)
	offset := int64(len(fileMagic))
	for offset < info.Size() {
		frameStart := offset
		remaining := info.Size() - offset
		if remaining < frameHeaderBytes {
			return events, frameStart, nil
		}
		frameHeader := make([]byte, frameHeaderBytes)
		if _, err := io.ReadFull(file, frameHeader); err != nil {
			return nil, -1, fmt.Errorf("read event frame header: %w", err)
		}
		offset += frameHeaderBytes
		length := int64(binary.BigEndian.Uint32(frameHeader[0:4]))
		if length <= 0 || length > maximumEventJSONBytes {
			return nil, -1, fmt.Errorf("%w: invalid frame length at byte %d", ErrCorrupt, frameStart)
		}
		if info.Size()-offset < length {
			return events, frameStart, nil
		}
		payload := make([]byte, length)
		if _, err := io.ReadFull(file, payload); err != nil {
			return nil, -1, fmt.Errorf("read event frame: %w", err)
		}
		offset += length
		expected := binary.BigEndian.Uint32(frameHeader[4:8])
		if crc32.Checksum(payload, checksumTable) != expected {
			if offset == info.Size() {
				return events, frameStart, nil
			}
			return nil, -1, fmt.Errorf("%w: checksum mismatch at byte %d", ErrCorrupt, frameStart)
		}
		event, err := decodeFrame(payload)
		if err != nil {
			return nil, -1, fmt.Errorf("%w: invalid event at byte %d: %v", ErrCorrupt, frameStart, err)
		}
		events = append(events, event)
	}
	return events, -1, nil
}
