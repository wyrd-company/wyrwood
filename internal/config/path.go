// ---
// relationships: {}
// ---

package config

import (
	"fmt"
	"os"
	"path/filepath"
)

// DefaultPath returns the platform-default per-user configuration file path.
func DefaultPath() (string, error) {
	root, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolve user configuration directory: %w", err)
	}
	if !filepath.IsAbs(root) {
		return "", fmt.Errorf("resolve user configuration directory: %q is not absolute", root)
	}
	return filepath.Join(root, "wyrwood", "config.yml"), nil
}
