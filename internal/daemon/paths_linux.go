//go:build linux

// ---
// relationships:
//   implements: linux-per-user-agent-proxy
// ---

package daemon

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

func defaultRuntimeRoot() (string, error) {
	root := os.Getenv("XDG_RUNTIME_DIR")
	if root == "" {
		root = filepath.Join("/run/user", strconv.Itoa(os.Geteuid()))
	}
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return "", errors.New("per-user runtime directory must be canonical and absolute")
	}
	return root, nil
}

func defaultStateRoot() (string, error) {
	root := os.Getenv("XDG_STATE_HOME")
	if root == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolve user home directory: %w", err)
		}
		root = filepath.Join(home, ".local", "state")
	}
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return "", errors.New("per-user state directory must be canonical and absolute")
	}
	return root, nil
}

// DefaultControlPath returns the control socket shared by local management
// surfaces and the per-user daemon.
func DefaultControlPath() (string, error) {
	runtimeRoot, err := defaultRuntimeRoot()
	if err != nil {
		return "", err
	}
	return filepath.Join(runtimeRoot, "wyrwood", "control.sock"), nil
}
