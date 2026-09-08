package main

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"regexp"
)

// Format-aware redaction that FAILS CLOSED. Round 2's regex-only version leaked
// on CRLF PEM, truncated PEM, and YAML block scalars. Round 3 normalizes line
// endings, parses PEM with encoding/pem (whole-file redaction if the envelope
// is incomplete), redacts YAML block scalars, and then runs a paranoia leak
// scan: if anything secret-shaped survives the format pass, the whole file
// collapses to REDACTED. The rule is: never emit bytes we are not sure about.

var secretKey = regexp.MustCompile(`(?i)(token|secret|password|api[_-]?key|_authtoken|\bkey\b|credential|private[_-]?key|refresh|access|id_token|bearer|oauth)`)

const redactedValue = "REDACTED"

// leaky matches things a redacted file must never still contain: PEM bodies,
// and long opaque token-shaped runs. It is deliberately aggressive; a false
// positive costs a whole-file redaction, which is the safe direction.
var leaky = regexp.MustCompile(`[A-Za-z0-9+/_-]{32,}`)

func redactForFormat(path string, b []byte) []byte {
	// Normalize CRLF so \r\n cannot hide a PEM envelope or a key boundary.
	b = bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))
	var out []byte
	switch {
	case bytes.Contains(b, []byte("-----BEGIN")):
		out = redactPEM(b)
	case looksJSON(b):
		if r, ok := redactJSON(b); ok {
			out = r
		} else {
			return whole()
		}
	case looksYAML(path) || bytes.ContainsAny(b, "=:"):
		out = redactYAMLLines(b)
	default:
		return whole()
	}
	// Paranoia gate: if any secret-shaped run survived, redact everything.
	if leaks(out) {
		return whole()
	}
	return out
}

func whole() []byte { return []byte(redactedValue + "\n") }

// leaks reports whether any token-shaped run survived that is not the REDACTED
// marker itself. A surviving PEM body, JWT, or opaque token is 32+ chars and is
// caught here; the cost of a false positive is a whole-file redaction. Fail
// closed on doubt.
func leaks(b []byte) bool {
	for _, m := range leaky.FindAll(b, -1) {
		if bytes.Equal(m, []byte(redactedValue)) {
			continue
		}
		return true
	}
	return false
}

func looksJSON(b []byte) bool {
	t := bytes.TrimSpace(b)
	return len(t) > 0 && (t[0] == '{' || t[0] == '[')
}

func looksYAML(path string) bool {
	return bytes.HasSuffix([]byte(path), []byte(".yml")) ||
		bytes.HasSuffix([]byte(path), []byte(".yaml"))
}

func redactJSON(b []byte) ([]byte, bool) {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, false
	}
	out, _ := json.MarshalIndent(walkJSON("", v), "", "  ")
	return append(out, '\n'), true
}

func walkJSON(key string, v any) any {
	switch t := v.(type) {
	case map[string]any:
		m := make(map[string]any, len(t))
		for k, val := range t {
			m[k] = walkJSON(k, val)
		}
		return m
	case []any:
		s := make([]any, len(t))
		for i, val := range t {
			s[i] = walkJSON(key, val)
		}
		return s
	default:
		if secretKey.MatchString(key) {
			return redactedValue
		}
		return v
	}
}

// redactPEM parses with encoding/pem. Every decoded block is re-emitted with a
// REDACTED body. If any bytes remain that still mention BEGIN (a truncated or
// malformed envelope pem.Decode could not consume), the whole file is redacted.
func redactPEM(b []byte) []byte {
	var buf bytes.Buffer
	rest := b
	for {
		blk, r := pem.Decode(rest)
		if blk == nil {
			break
		}
		buf.WriteString("-----BEGIN " + blk.Type + "-----\n")
		buf.WriteString(redactedValue + "\n")
		buf.WriteString("-----END " + blk.Type + "-----\n")
		rest = r
	}
	if bytes.Contains(rest, []byte("BEGIN")) || bytes.Contains(rest, []byte("END")) {
		return whole() // incomplete envelope: do not risk it
	}
	return buf.Bytes()
}

var kvLine = regexp.MustCompile(`(?i)^(\s*[^#\n].*(token|secret|password|api[_-]?key|_authtoken|key|credential|refresh|access|bearer|oauth)[^:=]*[:=]\s*)(.*)$`)
var blockScalar = regexp.MustCompile(`^[|>][+-]?\s*$`)

func redactYAMLLines(b []byte) []byte {
	lines := bytes.Split(b, []byte("\n"))
	for i := 0; i < len(lines); i++ {
		m := kvLine.FindSubmatch(lines[i])
		if m == nil {
			continue
		}
		val := bytes.TrimSpace(m[3])
		lines[i] = append(append([]byte{}, m[1]...), []byte(redactedValue)...)
		// Block scalar (`key: |` / `key: >`): redact the indented body that
		// follows, or the value would leak on the next lines.
		if len(val) == 0 || blockScalar.Match(val) {
			indent := leadingSpaces(m[1])
			for j := i + 1; j < len(lines); j++ {
				if len(bytes.TrimSpace(lines[j])) == 0 {
					continue
				}
				if leadingSpaces(lines[j]) <= indent {
					break
				}
				lines[j] = bytes.Repeat([]byte(" "), leadingSpaces(lines[j]))
				lines[j] = append(lines[j], []byte(redactedValue)...)
			}
		}
	}
	return bytes.Join(lines, []byte("\n"))
}

func leadingSpaces(b []byte) int {
	n := 0
	for n < len(b) && b[n] == ' ' {
		n++
	}
	return n
}
