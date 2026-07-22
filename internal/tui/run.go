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
	"os/signal"
	"sync/atomic"
	"syscall"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/muesli/termenv"
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
	profile := termenv.NewOutput(output).ColorProfile()
	colors := !noColor && os.Getenv("TERM") != "dumb" && profile != termenv.Ascii
	var interruptPending atomic.Bool
	model := NewModel(client, options{
		Colors: colors, ColorProfile: &profile,
		ResetInterrupt: func() { interruptPending.Store(false) },
	})
	defer model.close()
	program := tea.NewProgram(
		model,
		tea.WithInput(input),
		tea.WithOutput(output),
		tea.WithAltScreen(),
		tea.WithoutSignalHandler(),
	)
	signals := make(chan os.Signal, 2)
	done := make(chan struct{})
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer func() {
		signal.Stop(signals)
		close(done)
	}()
	go forwardSignals(program, signals, done, &interruptPending)
	_, err := program.Run()
	return normalizeRunError(err)
}

func forwardSignals(program *tea.Program, signals <-chan os.Signal, done <-chan struct{}, interruptPending *atomic.Bool) {
	for {
		select {
		case <-done:
			return
		case <-signals:
			if !interruptPending.CompareAndSwap(false, true) {
				program.Kill()
				return
			}
			program.Send(tea.KeyMsg{Type: tea.KeyCtrlC})
		}
	}
}

func normalizeRunError(err error) error {
	if err == nil || errors.Is(err, tea.ErrInterrupted) {
		return nil
	}
	if errors.Is(err, tea.ErrProgramKilled) && !errors.Is(err, tea.ErrProgramPanic) {
		return nil
	}
	return err
}
