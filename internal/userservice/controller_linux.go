//go:build linux

// ---
// relationships:
//   implements: linux-user-service
// ---

package userservice

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

const (
	systemctlTimeout       = 30 * time.Second
	maximumSystemctlOutput = 4 * 1024
)

type commandResult struct {
	exitCode int
	missing  bool
	output   []byte
	overflow bool
}

type commandRunner interface {
	run(string, ...string) commandResult
}

type execRunner struct{}

func (execRunner) run(name string, arguments ...string) commandResult {
	ctx, cancel := context.WithTimeout(context.Background(), systemctlTimeout)
	defer cancel()
	command := exec.CommandContext(ctx, name, arguments...)
	output := &boundedWriter{limit: maximumSystemctlOutput}
	command.Stdout = output
	command.Stderr = io.Discard
	err := command.Run()
	if err == nil {
		return commandResult{output: output.bytes(), overflow: output.overflow}
	}
	if errors.Is(err, exec.ErrNotFound) || errors.Is(err, os.ErrNotExist) {
		return commandResult{exitCode: -1, missing: true, output: output.bytes(), overflow: output.overflow}
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		return commandResult{exitCode: exitError.ExitCode(), output: output.bytes(), overflow: output.overflow}
	}
	return commandResult{exitCode: -1, output: output.bytes(), overflow: output.overflow}
}

type boundedWriter struct {
	buffer   bytes.Buffer
	limit    int
	overflow bool
}

func (writer *boundedWriter) Write(value []byte) (int, error) {
	accepted := len(value)
	remaining := writer.limit - writer.buffer.Len()
	if remaining < len(value) {
		writer.overflow = true
		value = value[:max(remaining, 0)]
	}
	_, _ = writer.buffer.Write(value)
	return accepted, nil
}

func (writer *boundedWriter) bytes() []byte {
	return append([]byte(nil), writer.buffer.Bytes()...)
}

type controller interface {
	reload() error
	enable(string) error
	tryRestart() error
	disableNow() error
	start() error
	stop() error
	status() (bool, State, error)
}

type systemdController struct{ runner commandRunner }

func (control systemdController) reload() error            { return control.mutate("daemon-reload") }
func (control systemdController) enable(path string) error { return control.mutate("enable", path) }
func (control systemdController) tryRestart() error        { return control.mutate("try-restart", UnitName) }
func (control systemdController) disableNow() error {
	return control.mutate("disable", "--now", UnitName)
}
func (control systemdController) start() error { return control.mutate("start", UnitName) }
func (control systemdController) stop() error  { return control.mutate("stop", UnitName) }

func (control systemdController) mutate(arguments ...string) error {
	result := control.invoke(arguments...)
	if result.missing {
		return ErrUnavailable
	}
	if result.exitCode != 0 {
		return ErrController
	}
	return nil
}

func (control systemdController) status() (bool, State, error) {
	result := control.invoke("show", UnitName, "--property=LoadState,UnitFileState,ActiveState")
	if result.missing {
		return false, "", ErrUnavailable
	}
	if result.exitCode != 0 || result.overflow {
		return false, "", ErrController
	}
	return parseStatusProjection(result.output)
}

func parseStatusProjection(output []byte) (bool, State, error) {
	if len(output) == 0 || len(output) > maximumSystemctlOutput || bytes.IndexByte(output, '\r') >= 0 || !bytes.HasSuffix(output, []byte("\n")) {
		return false, "", ErrController
	}
	values := make(map[string]string, 3)
	for _, line := range strings.Split(string(output[:len(output)-1]), "\n") {
		name, value, found := strings.Cut(line, "=")
		if !found || name == "" || value == "" {
			return false, "", ErrController
		}
		if _, duplicate := values[name]; duplicate {
			return false, "", ErrController
		}
		switch name {
		case "LoadState", "UnitFileState", "ActiveState":
			values[name] = value
		default:
			return false, "", ErrController
		}
	}
	if len(values) != 3 || values["LoadState"] != "loaded" {
		return false, "", ErrController
	}
	var enabled bool
	switch values["UnitFileState"] {
	case "enabled":
		enabled = true
	case "disabled":
	default:
		return false, "", ErrController
	}
	var state State
	switch values["ActiveState"] {
	case string(StateActive):
		state = StateActive
	case string(StateInactive):
		state = StateInactive
	case string(StateFailed):
		state = StateFailed
	default:
		return false, "", ErrController
	}
	return enabled, state, nil
}

func (control systemdController) invoke(arguments ...string) commandResult {
	prefix := []string{"--user", "--no-pager", "--no-ask-password"}
	return control.runner.run("systemctl", append(prefix, arguments...)...)
}
