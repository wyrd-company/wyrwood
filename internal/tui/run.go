//go:build linux

// ---
// relationships:
//   implements: terminal-interface
// ---

package tui

import (
	"errors"
	"io"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"golang.org/x/term"
)

var ErrNotTerminal = errors.New("interactive input and output terminals are required")

type fileDescriptor interface{ Fd() uintptr }

// Run validates terminal ownership before Bubble Tea can alter terminal state,
// then runs the application in an alternate screen. Bubble Tea restores the
// prior screen and input mode on every Run return path.
func Run(input io.Reader, output io.Writer, client Client) error {
	inputDescriptor, inputOK := input.(fileDescriptor)
	outputDescriptor, outputOK := output.(fileDescriptor)
	if !inputOK || !outputOK ||
		!term.IsTerminal(int(inputDescriptor.Fd())) ||
		!term.IsTerminal(int(outputDescriptor.Fd())) {
		return ErrNotTerminal
	}
	_, noColor := os.LookupEnv("NO_COLOR")
	colors := !noColor && os.Getenv("TERM") != "dumb"
	model := NewModel(client, options{Colors: colors})
	defer model.close()
	program := tea.NewProgram(
		model,
		tea.WithInput(input),
		tea.WithOutput(output),
		tea.WithAltScreen(),
		tea.WithContext(model.ctx),
	)
	_, err := program.Run()
	return err
}
