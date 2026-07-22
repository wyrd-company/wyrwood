//go:build linux && !race

// ---
// relationships:
//   verifies: terminal-interface
// ---

package tui

import (
	"bytes"
	"os"
	"os/exec"
	"reflect"
	"testing"
	"time"

	"github.com/creack/pty"
	"golang.org/x/sys/unix"
)

const interruptHelperEnvironment = "WYRWOOD_TUI_INTERRUPT_HELPER"

// The real-signal test is excluded from race builds because Bubble Tea's
// cancelreader dependency races internally while closing an interrupted input
// reader. Signal error classification remains covered in race builds.
func TestRunTreatsExternalInterruptAsCleanAndRestoresTerminal(t *testing.T) {
	if os.Getenv(interruptHelperEnvironment) == "1" {
		if err := Run(os.Stdin, os.Stdout, populatedClient()); err != nil {
			t.Fatalf("Run() external interrupt error = %v", err)
		}
		return
	}

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

	command := exec.Command(os.Args[0], "-test.run=^TestRunTreatsExternalInterruptAsCleanAndRestoresTerminal$")
	command.Env = append(os.Environ(), interruptHelperEnvironment+"=1", "TERM=xterm-256color", "NO_COLOR=1")
	command.Stdin = terminal
	command.Stdout = terminal
	command.Stderr = terminal
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}

	var rendered bytes.Buffer
	deadline := time.Now().Add(2 * time.Second)
	for !bytes.Contains(rendered.Bytes(), []byte("\x1b[?1049h")) && time.Now().Before(deadline) {
		drainPTY(t, controller, &rendered)
		time.Sleep(time.Millisecond)
	}
	if !bytes.Contains(rendered.Bytes(), []byte("\x1b[?1049h")) {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatalf("child application did not enter the alternate screen: %q", rendered.Bytes())
	}
	// Alternate-screen setup precedes Bubble Tea's signal handler by a few
	// scheduler turns. Let Run complete initialization before delivering SIGINT.
	time.Sleep(25 * time.Millisecond)
	if err := command.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	waitDone := make(chan error, 1)
	go func() { waitDone <- command.Wait() }()
	select {
	case err := <-waitDone:
		if err != nil {
			drainPTY(t, controller, &rendered)
			t.Fatalf("externally interrupted TUI did not exit cleanly: %v\n%s", err, rendered.String())
		}
	case <-time.After(2 * time.Second):
		_ = command.Process.Kill()
		<-waitDone
		t.Fatal("externally interrupted TUI did not exit")
	}

	after, err := unix.IoctlGetTermios(int(terminal.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(after, before) {
		t.Fatalf("terminal mode changed after external interrupt\nbefore: %#v\nafter:  %#v", before, after)
	}
	drainPTY(t, controller, &rendered)
	if !bytes.Contains(rendered.Bytes(), []byte("\x1b[?1049l")) {
		t.Fatalf("external interrupt did not restore the prior screen: %q", rendered.Bytes())
	}
}

func TestRunDirtyEditorRequiresSecondExternalInterruptAndRestoresTerminal(t *testing.T) {
	controller, terminal, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer controller.Close()
	defer terminal.Close()
	if err := pty.Setsize(terminal, &pty.Winsize{Rows: 34, Cols: 118}); err != nil {
		t.Fatal(err)
	}
	before, err := unix.IoctlGetTermios(int(terminal.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}

	command := exec.Command(os.Args[0], "-test.run=^TestRunTreatsExternalInterruptAsCleanAndRestoresTerminal$")
	command.Env = append(os.Environ(), interruptHelperEnvironment+"=1", "TERM=xterm-256color", "NO_COLOR=1")
	command.Stdin, command.Stdout, command.Stderr = terminal, terminal, terminal
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	var rendered bytes.Buffer
	waitForPTYText(t, controller, &rendered, "DASHBOARD")
	if _, err := controller.Write([]byte("s")); err != nil {
		t.Fatal(err)
	}
	waitForPTYText(t, controller, &rendered, "SETTINGS / TIMEOUTS")
	if _, err := controller.Write([]byte("\x7f\x7f6s")); err != nil {
		t.Fatal(err)
	}
	waitForPTYText(t, controller, &rendered, "DIRTY")
	if err := command.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	waitForPTYText(t, controller, &rendered, "Discard local edits and exit?")

	waitDone := make(chan error, 1)
	go func() { waitDone <- command.Wait() }()
	select {
	case err := <-waitDone:
		t.Fatalf("first interrupt exited dirty editor: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	if err := command.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-waitDone:
		if err != nil {
			drainPTY(t, controller, &rendered)
			t.Fatalf("second interrupt was not clean: %v\n%s", err, rendered.String())
		}
	case <-time.After(2 * time.Second):
		_ = command.Process.Kill()
		<-waitDone
		t.Fatal("second interrupt did not exit")
	}
	after, err := unix.IoctlGetTermios(int(terminal.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(after, before) {
		t.Fatalf("terminal mode changed after dirty interrupt\nbefore: %#v\nafter:  %#v", before, after)
	}
	drainPTY(t, controller, &rendered)
	if !bytes.Contains(rendered.Bytes(), []byte("\x1b[?1049l")) {
		t.Fatalf("dirty interrupt did not restore prior screen: %q", rendered.Bytes())
	}
}
