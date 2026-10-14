// ---
// relationships:
//   implements: configuration
// ---

// Package config owns the agent and controller configuration documents.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	// MaximumDocumentBytes bounds both configuration documents.
	MaximumDocumentBytes = 1 << 20
	maximumSecretBytes   = 64 << 10

	// DefaultAgentPath is the agent configuration document.
	DefaultAgentPath = "/etc/wyrwood/agent.yml"
	// DefaultControllerPath is the controller configuration document.
	DefaultControllerPath = "/etc/wyrwood/controller.yml"
)

var (
	controllerURLPattern = regexp.MustCompile(`^ssh://[^/]+(:[0-9]+)?$`)
	durationPattern      = regexp.MustCompile(`^[0-9]+(ms|s|m)$`)
)

// ErrInvalid wraps every configuration rejection.
var ErrInvalid = errors.New("invalid configuration")

func invalid(format string, arguments ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, arguments...))
}

// decodeStrict parses one YAML document with unknown fields rejected.
func decodeStrict(data []byte, destination any) error {
	if len(data) > MaximumDocumentBytes {
		return invalid("document exceeds 1 MiB")
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(destination); err != nil {
		if errors.Is(err, io.EOF) {
			return invalid("document is empty")
		}
		return invalid("%v", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return invalid("document must contain exactly one YAML document")
	}
	return nil
}

func readBounded(path string, maximum int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maximum {
		return nil, invalid("file exceeds %d bytes", maximum)
	}
	return data, nil
}

// ReadSecretFile reads a secret from a mounted file, trimming one trailing
// newline. The value is never part of a configuration document.
func ReadSecretFile(path string) (string, error) {
	data, err := readBounded(path, maximumSecretBytes)
	if err != nil {
		return "", fmt.Errorf("read secret file: %w", err)
	}
	value := strings.TrimRight(string(data), "\r\n")
	if value == "" || strings.ContainsAny(value, "\r\n\x00") {
		return "", invalid("secret file must contain one non-empty line")
	}
	return value, nil
}

func canonicalPath(field, value string) (string, error) {
	if value == "" || !filepath.IsAbs(value) || strings.IndexByte(value, 0) >= 0 {
		return "", invalid("%s must be an absolute path", field)
	}
	cleaned := filepath.Clean(value)
	if cleaned == "/" {
		return "", invalid("%s must not be the filesystem root", field)
	}
	return cleaned, nil
}

func parseBoundedDuration(field, value string, minimum, maximum time.Duration) (time.Duration, error) {
	duration, err := time.ParseDuration(value)
	if err != nil {
		return 0, invalid("%s must use Go duration syntax", field)
	}
	if duration < minimum || duration > maximum {
		return 0, invalid("%s must be between %s and %s", field, minimum, maximum)
	}
	return duration, nil
}

func validListen(field, value string) error {
	host, port, err := net.SplitHostPort(value)
	if err != nil {
		return invalid("%s must be host:port", field)
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return invalid("%s port is invalid", field)
	}
	if host != "" && net.ParseIP(host) == nil && strings.ContainsAny(host, " /") {
		return invalid("%s host is invalid", field)
	}
	return nil
}

func absoluteURL(field, value string, schemes ...string) (*url.URL, error) {
	parsed, err := url.Parse(value)
	if err != nil || !parsed.IsAbs() || parsed.Host == "" {
		return nil, invalid("%s must be an absolute URL", field)
	}
	for _, scheme := range schemes {
		if parsed.Scheme == scheme {
			return parsed, nil
		}
	}
	return nil, invalid("%s must use %s", field, strings.Join(schemes, " or "))
}
