// ---
// relationships: {}
// ---

package config

import (
	"encoding/base64"
	"fmt"
	"math"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"
)

// Validate checks every cross-field and semantic configuration invariant.
func Validate(configuration Config) error {
	if err := validateSocketPath("upstream", configuration.Upstream); err != nil {
		return err
	}
	if err := validateTimeout("timeouts.connect", configuration.Timeouts.Connect, minimumShortTimeout, maximumShortTimeout); err != nil {
		return err
	}
	if err := validateTimeout("timeouts.list", configuration.Timeouts.List, minimumShortTimeout, maximumShortTimeout); err != nil {
		return err
	}
	if err := validateTimeout("timeouts.replay", configuration.Timeouts.Replay, minimumShortTimeout, maximumShortTimeout); err != nil {
		return err
	}
	if err := validateTimeout("timeouts.sign", configuration.Timeouts.Sign, minimumSignTimeout, maximumSignTimeout); err != nil {
		return err
	}

	names := make(map[string]int, len(configuration.Consumers))
	sockets := map[string]string{configuration.Upstream: "upstream"}
	parents := make([]string, 0, len(configuration.Consumers))
	for index, consumer := range configuration.Consumers {
		path := fmt.Sprintf("consumers[%d]", index)
		if consumer.Name == "" {
			return fieldError(path+".name", "must not be empty")
		}
		if !utf8.ValidString(consumer.Name) || utf8.RuneCountInString(consumer.Name) > MaximumConsumerNameCharacters {
			return fieldError(path+".name", fmt.Sprintf("must contain at most %d Unicode characters", MaximumConsumerNameCharacters))
		}
		if strings.TrimSpace(consumer.Name) != consumer.Name {
			return fieldError(path+".name", "must not have leading or trailing whitespace")
		}
		if first, exists := names[consumer.Name]; exists {
			return fieldError(path+".name", fmt.Sprintf("duplicates consumers[%d].name", first))
		}
		names[consumer.Name] = index

		if err := validateSocketPath(path+".socket", consumer.Socket); err != nil {
			return err
		}
		if first, exists := sockets[consumer.Socket]; exists {
			return fieldError(path+".socket", fmt.Sprintf("duplicates %s", first))
		}
		sockets[consumer.Socket] = path + ".socket"

		parent := filepath.Dir(consumer.Socket)
		if parent == string(filepath.Separator) {
			return fieldError(path+".socket", "must have a dedicated parent directory below the filesystem root")
		}
		if pathContains(parent, configuration.Upstream) {
			return fieldError(path+".socket", "parent directory must not contain the upstream socket")
		}
		for prior, otherParent := range parents {
			if pathContains(parent, otherParent) || pathContains(otherParent, parent) {
				return fieldError(path+".socket", fmt.Sprintf("parent directory overlaps consumers[%d].socket parent", prior))
			}
		}
		parents = append(parents, parent)

		if consumer.AccessGroup != nil && *consumer.AccessGroup == math.MaxUint32 {
			return fieldError(path+".access-group", "must be between 0 and 4294967294")
		}
		fingerprints := make(map[string]int, len(consumer.Fingerprints))
		for fingerprintIndex, fingerprint := range consumer.Fingerprints {
			fingerprintPath := fmt.Sprintf("%s.fingerprints[%d]", path, fingerprintIndex)
			if err := validateFingerprint(fingerprintPath, fingerprint); err != nil {
				return err
			}
			if first, exists := fingerprints[fingerprint]; exists {
				return fieldError(fingerprintPath, fmt.Sprintf("duplicates %s.fingerprints[%d]", path, first))
			}
			fingerprints[fingerprint] = fingerprintIndex
		}
	}
	return nil
}

func validateSocketPath(field, value string) error {
	if value == "" {
		return fieldError(field, "must not be empty")
	}
	if strings.IndexByte(value, 0) >= 0 {
		return fieldError(field, "must not contain a NUL byte")
	}
	if !filepath.IsAbs(value) {
		return fieldError(field, "must be an absolute path")
	}
	if value == string(filepath.Separator) {
		return fieldError(field, "must name a socket below the filesystem root")
	}
	if filepath.Clean(value) != value {
		return fieldError(field, "must be in canonical lexical form")
	}
	return nil
}

func validateFingerprint(field, value string) error {
	const prefix = "SHA256:"
	if !strings.HasPrefix(value, prefix) {
		return fieldError(field, "must use the SHA256: prefix")
	}
	encoded := strings.TrimPrefix(value, prefix)
	decoded, err := base64.RawStdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(decoded) != 32 || base64.RawStdEncoding.EncodeToString(decoded) != encoded {
		return fieldError(field, "must contain the canonical unpadded base64 encoding of a 32-byte SHA-256 digest")
	}
	return nil
}

func validateTimeout(field string, value, minimum, maximum time.Duration) error {
	if value < minimum || value > maximum {
		return fieldError(field, fmt.Sprintf("must be between %s and %s", minimum, maximum))
	}
	return nil
}

func pathContains(parent, candidate string) bool {
	relative, err := filepath.Rel(parent, candidate)
	if err != nil {
		return false
	}
	return relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)))
}
