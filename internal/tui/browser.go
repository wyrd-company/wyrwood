//go:build linux

// ---
// relationships:
//   implements: terminal-interface
// ---

package tui

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
)

const (
	maximumBrowserEntries     = 256
	maximumBrowserScanEntries = 512
)

// SocketEntry is one bounded, advisory filesystem choice. Selecting it changes
// editable text only; it grants no authority and proves no agent reachability.
type SocketEntry struct {
	Path      string
	Directory bool
	Socket    bool
}

type SocketListing struct {
	Entries   []SocketEntry
	Truncated bool
}

type SocketBrowser interface {
	Browse(context.Context, string) (SocketListing, error)
}

type linuxSocketBrowser struct{}

func (linuxSocketBrowser) Browse(ctx context.Context, parent string) (SocketListing, error) {
	if !filepath.IsAbs(parent) {
		return SocketListing{}, errors.New("browser path is not absolute")
	}
	directory, err := os.Open(parent)
	if err != nil {
		return SocketListing{}, errors.New("browse socket directory")
	}
	defer directory.Close()
	entries, err := directory.ReadDir(maximumBrowserScanEntries + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return SocketListing{}, errors.New("browse socket directory")
	}
	truncated := len(entries) > maximumBrowserScanEntries
	if truncated {
		entries = entries[:maximumBrowserScanEntries]
	}
	result := make([]SocketEntry, 0, min(len(entries), maximumBrowserEntries))
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return SocketListing{}, err
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if !info.IsDir() && info.Mode()&os.ModeSocket == 0 {
			continue
		}
		result = append(result, SocketEntry{
			Path: filepath.Join(parent, entry.Name()), Directory: info.IsDir(), Socket: info.Mode()&os.ModeSocket != 0,
		})
		if len(result) == maximumBrowserEntries {
			truncated = true
			break
		}
	}
	sort.Slice(result, func(left, right int) bool { return result[left].Path < result[right].Path })
	return SocketListing{Entries: result, Truncated: truncated}, nil
}

type browserViewState struct {
	active    bool
	loading   bool
	parent    string
	entries   []SocketEntry
	truncated bool
	index     int
	state     loadState
}

type browserMsg struct {
	request uint64
	parent  string
	listing SocketListing
	err     error
}

var _ SocketBrowser = linuxSocketBrowser{}
