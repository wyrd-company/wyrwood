// ---
// relationships:
//   implements: agent-controller-protocol
// ---

package protocol

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// MaximumDirectoryNameBytes bounds a consumer directory name.
const MaximumDirectoryNameBytes = 255

// The refusals of a consumer directory name, so that a caller can tell them
// apart without reading their text.
var (
	ErrDirectoryNameEmpty      = errors.New("the directory name is required")
	ErrDirectoryNameSeparator  = errors.New("the directory name must not contain a path separator")
	ErrDirectoryNameDots       = errors.New("the directory name must not be . or ..")
	ErrDirectoryNameLength     = fmt.Errorf("the directory name exceeds %d bytes", MaximumDirectoryNameBytes)
	ErrDirectoryNameCharacters = errors.New("the directory name must start with a letter or digit and use only letters, digits, '.', '_', and '-'")
	// ErrDirectoryNameForName refuses a directory name on a name key, whose
	// value already names the directory.
	ErrDirectoryNameForName = errors.New("a name key names its own directory; a directory name is accepted only for another key kind")
)

var directoryNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)

// ValidateDirectoryName applies the one rule for a consumer directory name: the
// rule that a container name, and so a name key, must meet to name one. It is 1
// to 255 bytes of letters, digits, '.', '_', and '-', starts with a letter or
// digit, and is neither . nor .., so that it is one path element under the
// consumer root.
func ValidateDirectoryName(name string) error {
	switch {
	case name == "":
		return ErrDirectoryNameEmpty
	case strings.ContainsRune(name, '/'):
		return ErrDirectoryNameSeparator
	case name == "." || name == "..":
		return ErrDirectoryNameDots
	case len(name) > MaximumDirectoryNameBytes:
		return ErrDirectoryNameLength
	case !directoryNamePattern.MatchString(name):
		return ErrDirectoryNameCharacters
	}
	return nil
}

// ValidDirectoryName reports whether name is a valid consumer directory name.
func ValidDirectoryName(name string) bool { return ValidateDirectoryName(name) == nil }
