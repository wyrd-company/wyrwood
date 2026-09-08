package main

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"regexp"
)

// Fail-closed redaction by ALLOWLIST. Rounds 2-3 redacted known secret key
// NAMES (a denylist) and scanned for long runs; that structurally cannot fail
// closed — an unmodeled key (`pin`, `session`) or a short value slips through.
// Round 4 inverts it: a scalar value is emitted only when its key is on an
// explicit safe list; every other value is REDACTED regardless of name or
// length. Redacted output is only ever served to NON-allowlisted readers, who
// are meant to fail; anyone who needs the real bytes is allowlisted and gets
// the file unredacted. So the only contract on redacted output is "leaks
// nothing" — validity and completeness are not promised, and this over-redacts
// by design.

const redactedValue = "REDACTED"

// safeKeys are field names known to carry no secret in the inventoried config
// files. Everything not listed is redacted. Keep this small and conservative:
// a wrong entry here is the only way a secret leaks.
var safeKeys = map[string]bool{
	"user": true, "users": true, "git_protocol": true, "host": true,
	"hosts": true, "registry": true, "prefix": true, "editor": true,
	"version": true, "schema": true, "protocol": true, "provider": true,
	"providers": true, "model": true, "theme": true, "email": true,
}

// leaky is a belt-and-suspenders scan for long opaque runs that survived. With
// the allowlist it should never fire, but if it does the file collapses whole.
var leaky = regexp.MustCompile(`[A-Za-z0-9+/_-]{32,}`)

func redactForFormat(path string, b []byte) []byte {
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
		out = redactKVLines(b)
	default:
		return whole()
	}
	if leaks(out) {
		return whole()
	}
	return out
}

func whole() []byte { return []byte(redactedValue + "\n") }

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

// walkJSON keeps a scalar only when its key is safe; every other scalar becomes
// REDACTED. Output stays valid JSON.
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
		if safeKeys[key] {
			return v
		}
		return redactedValue
	}
}

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
		return whole()
	}
	return buf.Bytes()
}

// keyOf extracts the field name from a `  key: value` or `key=value` line.
var keyOf = regexp.MustCompile(`^(\s*)([^#\s:=][^:=]*?)\s*[:=]\s*(.*)$`)

// redactKVLines keeps a scalar value only for a safe key; any other key's value
// is redacted, and a redacted key's block-scalar body (indented follow-on
// lines) is redacted too. A `key:` with no inline value that is NOT safe also
// has its following indented block redacted.
func redactKVLines(b []byte) []byte {
	lines := bytes.Split(b, []byte("\n"))
	for i := 0; i < len(lines); i++ {
		m := keyOf.FindSubmatch(lines[i])
		if m == nil {
			continue
		}
		indent := len(m[1])
		key := string(bytes.ToLower(bytes.TrimSpace(m[2])))
		val := bytes.TrimSpace(m[3])
		if safeKeys[key] {
			continue // safe scalar or safe mapping header: leave as-is
		}
		if len(val) > 0 {
			// unsafe key with an inline value: redact the value, keep the key
			lines[i] = append(append([]byte{}, m[1]...), append(bytes.TrimRight(m[2], " "), append([]byte(": "), []byte(redactedValue)...)...)...)
		}
		// Redact any deeper-indented body under this unsafe key (block scalar
		// or nested mapping of unsafe fields), stopping at the next sibling.
		for j := i + 1; j < len(lines); j++ {
			if len(bytes.TrimSpace(lines[j])) == 0 {
				continue
			}
			if leadingSpaces(lines[j]) <= indent {
				break
			}
			// only redact scalar bodies (lines that are not safe mapping keys)
			cm := keyOf.FindSubmatch(lines[j])
			if cm != nil && safeKeys[string(bytes.ToLower(bytes.TrimSpace(cm[2])))] {
				continue
			}
			lines[j] = append(bytes.Repeat([]byte(" "), leadingSpaces(lines[j])), []byte(redactedValue)...)
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
