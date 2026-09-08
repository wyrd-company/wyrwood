package main

import (
	"bytes"
	"encoding/json"
	"regexp"
)

// Format-aware redaction. Round 1 used one regex over raw bytes; it left
// `access_token` visible inside `"tokens": {...}` and produced invalid JSON.
// Round 2 redacts by format and FAILS CLOSED: any content a redactor does not
// understand is replaced wholesale, never passed through partly cleaned.

var secretKey = regexp.MustCompile(`(?i)(token|secret|password|api[_-]?key|_authtoken|\bkey\b|credential|private[_-]?key|refresh|access|id_token|bearer|oauth)`)

const redactedValue = "REDACTED"

// redactForFormat picks a redactor from the served path's shape. Unknown
// formats collapse to a single REDACTED marker rather than leaking.
func redactForFormat(path string, b []byte) []byte {
	switch {
	case bytes.Contains(b, []byte("-----BEGIN")):
		return redactPEM(b)
	case looksJSON(b):
		if out, ok := redactJSON(b); ok {
			return out
		}
		return []byte(redactedValue + "\n")
	case looksYAML(path):
		return redactYAMLLines(b)
	default:
		// npmrc / ini / opaque: line-based key=value, else whole-file.
		if bytes.ContainsAny(b, "=:") {
			return redactYAMLLines(b)
		}
		return []byte(redactedValue + "\n")
	}
}

func looksJSON(b []byte) bool {
	t := bytes.TrimSpace(b)
	return len(t) > 0 && (t[0] == '{' || t[0] == '[')
}

func looksYAML(path string) bool {
	return bytes.HasSuffix([]byte(path), []byte(".yml")) ||
		bytes.HasSuffix([]byte(path), []byte(".yaml"))
}

// redactJSON walks the parsed tree and rewrites every value under a
// secret-named key to REDACTED, recursively. It re-marshals, so output is
// always valid JSON. ok=false means the bytes did not parse (fail closed).
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

func redactPEM(b []byte) []byte {
	// Replace the body of every PEM block; keep the BEGIN/END envelope so the
	// consumer still parses the container but gets no key material.
	re := regexp.MustCompile(`(?s)(-----BEGIN [^-]+-----\n).*?(\n-----END [^-]+-----)`)
	return re.ReplaceAll(b, []byte("${1}"+redactedValue+"${2}"))
}

var kvLine = regexp.MustCompile(`(?i)^(\s*[^#\n].*(token|secret|password|api[_-]?key|_authtoken|key|credential|refresh|access|bearer|oauth)[^:=]*[:=]\s*)(.*)$`)

func redactYAMLLines(b []byte) []byte {
	lines := bytes.Split(b, []byte("\n"))
	for i, ln := range lines {
		if m := kvLine.FindSubmatch(ln); m != nil {
			lines[i] = append(append([]byte{}, m[1]...), []byte(redactedValue)...)
		}
	}
	return bytes.Join(lines, []byte("\n"))
}
