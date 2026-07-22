//go:build linux

// ---
// relationships:
//   verifies: terminal-interface
// ---

package tui

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/creack/pty"
	"golang.org/x/sys/unix"
)

func TestNormalizeRunErrorTreatsExpectedSignalExitsAsClean(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		wantClean bool
	}{
		{name: "nil", wantClean: true},
		{name: "interrupt", err: tea.ErrInterrupted, wantClean: true},
		{name: "wrapped interrupt", err: fmt.Errorf("terminal: %w", tea.ErrInterrupted), wantClean: true},
		{name: "killed", err: tea.ErrProgramKilled, wantClean: true},
		{name: "wrapped killed", err: fmt.Errorf("signal: %w", tea.ErrProgramKilled), wantClean: true},
		{name: "unknown", err: errors.New("unexpected")},
		{name: "panic", err: fmt.Errorf("%w: %w", tea.ErrProgramKilled, tea.ErrProgramPanic)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := normalizeRunError(test.err)
			if test.wantClean && got != nil {
				t.Fatalf("normalizeRunError(%v) = %v, want clean exit", test.err, got)
			}
			if !test.wantClean && got == nil {
				t.Fatalf("normalizeRunError(%v) suppressed unexpected failure", test.err)
			}
		})
	}
}

func TestRunRestoresTerminalModeAndAlternateScreen(t *testing.T) {
	t.Setenv("TERM", "xterm-256color")
	t.Setenv("NO_COLOR", "1")
	controller, terminal, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer controller.Close()
	defer terminal.Close()
	before, err := unix.IoctlGetTermios(int(terminal.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}

	runDone := make(chan error, 1)
	go func() { runDone <- Run(terminal, terminal, populatedClient()) }()
	var rendered bytes.Buffer
	deadline := time.Now().Add(2 * time.Second)
	for !bytes.Contains(rendered.Bytes(), []byte("\x1b[?1049h")) && time.Now().Before(deadline) {
		drainPTY(t, controller, &rendered)
		time.Sleep(time.Millisecond)
	}
	if !bytes.Contains(rendered.Bytes(), []byte("\x1b[?1049h")) {
		t.Fatal("application did not enter the alternate screen")
	}
	if _, err := controller.Write([]byte("q")); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("Run() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run() did not exit after keyboard quit")
	}
	after, err := unix.IoctlGetTermios(int(terminal.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(after, before) {
		t.Fatalf("terminal mode changed after exit\nbefore: %#v\nafter:  %#v", before, after)
	}
	drainPTY(t, controller, &rendered)
	output := rendered.Bytes()
	if !bytes.Contains(output, []byte("\x1b[?1049h")) || !bytes.Contains(output, []byte("\x1b[?1049l")) {
		t.Fatalf("alternate-screen enter/leave sequences absent: %q", output)
	}
}

func drainPTY(t *testing.T, controller interface {
	Fd() uintptr
}, output *bytes.Buffer) {
	t.Helper()
	buffer := make([]byte, 4096)
	for {
		descriptors := []unix.PollFd{{Fd: int32(controller.Fd()), Events: unix.POLLIN}}
		ready, err := unix.Poll(descriptors, 0)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if ready == 0 || descriptors[0].Revents&unix.POLLIN == 0 {
			return
		}
		count, err := unix.Read(int(controller.Fd()), buffer)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		output.Write(buffer[:count])
		if count == 0 {
			return
		}
	}
}
