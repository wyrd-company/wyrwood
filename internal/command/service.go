// ---
// relationships:
//   implements:
//     - command-line-interface
//     - linux-service
// ---

package command

import (
	"errors"
	"fmt"
	"io"

	"github.com/wyrd-company/wyrwood/internal/linuxservice"
)

func runService(args []string, stdout, stderr io.Writer, deps dependencies) int {
	name := "agent service"
	if len(args) == 0 {
		return writeFailure(stderr, outputHuman, name, failureUsage)
	}
	action := args[0]
	switch action {
	case "install", "remove", "start", "stop", "status":
	default:
		return writeFailure(stderr, outputHuman, name, failureUsage)
	}
	options, positional, problem := parseOptions(args[1:], optionOutput)
	if options.help {
		_, _ = io.WriteString(stdout, "Usage: wyrwood agent service install|remove|start|stop|status [--output human|json]\n")
		return exitSuccess
	}
	if problem != nil || len(positional) != 0 {
		return writeFailure(stderr, options.output, name, failureUsage)
	}
	state, err := deps.manageService(action)
	if err != nil {
		return writeFailure(stderr, options.output, name, serviceFailure(err))
	}
	if options.output == outputJSON {
		return writeJSON(stdout, struct {
			Version int    `json:"version"`
			Action  string `json:"action"`
			State   string `json:"state"`
		}{outputVersion, action, state})
	}
	_, _ = fmt.Fprintf(stdout, "wyrwood-agent.service: %s\n", state)
	return exitSuccess
}

func serviceFailure(err error) failure {
	switch {
	case errors.Is(err, linuxservice.ErrRequiresRoot):
		return failureRequiresRoot
	case errors.Is(err, linuxservice.ErrNotInstalled):
		return failureNotInstalled
	default:
		return failureServiceManager
	}
}
