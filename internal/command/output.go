// ---
// relationships:
//   implements: command-line-interface
// ---

package command

import (
	"encoding/json"
	"fmt"
	"io"
)

// Exit statuses are part of the command-line contract.
const (
	exitSuccess       = 0
	exitOperational   = 1
	exitUsage         = 2
	exitLoginState    = 3
	exitDaemon        = 4
	exitNotApproved   = 5
	exitUnreachable   = 6
	exitHostKeyChange = 7
)

// outputVersion is the version of every JSON projection the executable emits.
const outputVersion = 1

type outputFormat string

const (
	outputHuman outputFormat = "human"
	outputJSON  outputFormat = "json"
)

// failure is a categorical error projection. The code is closed vocabulary
// and the message is fixed text; neither carries raw error detail.
type failure struct {
	code    string
	message string
	status  int
}

var (
	failureUsage          = failure{"usage", "invalid usage", exitUsage}
	failureOperational    = failure{"operational", "operation failed", exitOperational}
	failureConfiguration  = failure{"configuration", "configuration is invalid or unreadable", exitOperational}
	failureLoginState     = failure{"login-state", "agent key or login state unavailable", exitLoginState}
	failureDaemon         = failure{"daemon-unavailable", "agent daemon control socket unavailable", exitDaemon}
	failureNotApproved    = failure{"not-approved", "controller refused or has not approved this agent", exitNotApproved}
	failureUnreachable    = failure{"controller-unreachable", "controller unreachable", exitUnreachable}
	failureHostKey        = failure{"host-key-mismatch", "controller host-key fingerprint does not match", exitHostKeyChange}
	failureNotAccepted    = failure{"fingerprint-not-accepted", "controller host-key fingerprint was not accepted", exitHostKeyChange}
	failureRequiresRoot   = failure{"requires-root", "this command requires root", exitOperational}
	failureServiceManager = failure{"service-manager", "system service manager operation failed", exitOperational}
	failureStateDirectory = failure{"state-unavailable", "controller state unavailable", exitOperational}
)

type failureProjection struct {
	Version int    `json:"version"`
	Command string `json:"command"`
	Error   string `json:"error"`
}

func writeFailure(stderr io.Writer, format outputFormat, command string, problem failure) int {
	if format == outputJSON {
		_ = json.NewEncoder(stderr).Encode(failureProjection{Version: outputVersion, Command: command, Error: problem.code})
		return problem.status
	}
	_, _ = fmt.Fprintf(stderr, "wyrwood %s: %s\n", command, problem.message)
	return problem.status
}

func writeJSON(stdout io.Writer, value any) int {
	encoder := json.NewEncoder(stdout)
	if err := encoder.Encode(value); err != nil {
		return exitOperational
	}
	return exitSuccess
}
