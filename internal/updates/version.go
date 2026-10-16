// ---
// relationships:
//   implements: web-interface
// ---

// Package updates checks public releases and compares build versions.
package updates

import (
	"golang.org/x/mod/semver"
	"strings"
)

// Valid reports whether value is a complete SemVer, with an optional v prefix.
func Valid(value string) bool {
	value = strings.TrimPrefix(value, "v")
	core, _, _ := strings.Cut(value, "-")
	core, _, _ = strings.Cut(core, "+")
	return strings.Count(core, ".") == 2 && semver.IsValid("v"+value)
}

// Older compares valid build versions using SemVer precedence. Unknown and
// development builds do not imply an available update.
func Older(current, other string) bool {
	return Valid(current) && Valid(other) &&
		semver.Compare("v"+strings.TrimPrefix(current, "v"), "v"+strings.TrimPrefix(other, "v")) < 0
}
