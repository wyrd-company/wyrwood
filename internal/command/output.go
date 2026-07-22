// ---
// relationships:
//   implements: command-line-interface
//   projects: control-interface
// ---

package command

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/wyrd-company/wyrwood/internal/control"
	"github.com/wyrd-company/wyrwood/internal/userservice"
)

const (
	exitSuccess           = 0
	exitOperational       = 1
	exitUsage             = 2
	exitInitialization    = 3
	exitDaemonUnavailable = 4
	exitApplyInvalid      = 5
	exitRequestFailed     = 6
	exitUpstream          = 7
)

type initResult struct {
	Path string `json:"path"`
}

type successEnvelope struct {
	Version int    `json:"version"`
	Command string `json:"command"`
	OK      bool   `json:"ok"`
	Result  any    `json:"result"`
}

type errorProjection struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Action  string `json:"action"`
}

type failureEnvelope struct {
	Version int             `json:"version"`
	Command string          `json:"command"`
	OK      bool            `json:"ok"`
	Error   errorProjection `json:"error"`
}

type failure struct {
	code     string
	message  string
	action   string
	exitCode int
}

var (
	failureUsage = failure{
		code: "usage", message: "command options are invalid",
		action: "Run 'wyrwood help' or 'wyrwood <command> --help' for usage.", exitCode: exitUsage,
	}
	failureInitialize = failure{
		code: "initialization-failed", message: "configuration was not created",
		action: "Set SSH_AUTH_SOCK to a canonical absolute socket path, or inspect the existing default configuration.", exitCode: exitInitialization,
	}
	failureDurability = failure{
		code: "durability-uncertain", message: "configuration was created, but its durability could not be confirmed",
		action: "Inspect the default configuration before retrying.", exitCode: exitInitialization,
	}
	failureDaemonUnavailable = failure{
		code: "daemon-unavailable", message: "the daemon request could not be completed",
		action: "Start 'wyrwood daemon' and verify its owner-only runtime directory.", exitCode: exitDaemonUnavailable,
	}
	failureUncommitted = failure{
		code: "apply-failed", message: "the daemon did not commit the configuration",
		action: "Inspect 'wyrwood status' and 'wyrwood events' before retrying.", exitCode: exitRequestFailed,
	}
	failureServiceUnavailable = failure{
		code: "service-unavailable", message: "the systemd user manager is unavailable",
		action: "Use a Linux login session with systemd user services and retry.", exitCode: exitOperational,
	}
	failureService = failure{
		code: "service-failed", message: "the per-user service operation did not complete",
		action: "Inspect the user unit and systemd user-manager state before retrying.", exitCode: exitOperational,
	}
)

func failurePointer(value failure) *failure { return &value }

func classifyRequestFailure(err error) failure {
	if errors.Is(err, errUncommittedApply) {
		return failureUncommitted
	}
	var remote *control.RemoteError
	if !errors.As(err, &remote) {
		return failureDaemonUnavailable
	}
	switch remote.Code {
	case control.ErrorApplyInvalid:
		return failure{code: "apply-invalid", message: "the default configuration was rejected", action: "Correct the default configuration and run 'wyrwood apply' again.", exitCode: exitApplyInvalid}
	case control.ErrorApplyFailed:
		return failure{code: "apply-failed", message: "the configuration could not be applied", action: "Resolve consumer path or permission conflicts, then retry.", exitCode: exitRequestFailed}
	case control.ErrorUpstreamUnavailable:
		return failure{code: "upstream-unavailable", message: "the configured upstream agent is unavailable", action: "Restore the configured upstream agent and retry.", exitCode: exitUpstream}
	case control.ErrorResourceLimit:
		return failure{code: "resource-limit", message: "the request exceeded a daemon resource limit", action: "Reduce the requested or configured result set and retry.", exitCode: exitRequestFailed}
	case control.ErrorBadRequest:
		return failure{code: "request-rejected", message: "the daemon rejected the request", action: "Verify that the CLI and daemon versions match.", exitCode: exitRequestFailed}
	case control.ErrorUnsupportedVersion:
		return failure{code: "incompatible-daemon", message: "the CLI and daemon protocol versions do not match", action: "Run matching Wyrwood CLI and daemon versions.", exitCode: exitDaemonUnavailable}
	default:
		return failure{code: "daemon-failed", message: "the daemon could not complete the request", action: "Inspect 'wyrwood status' and 'wyrwood events' before retrying.", exitCode: exitRequestFailed}
	}
}

func writeFailure(stderr io.Writer, format outputFormat, command string, problem failure) int {
	if format == outputJSON {
		_ = writeJSON(stderr, failureEnvelope{
			Version: 1, Command: command, OK: false,
			Error: errorProjection{Code: problem.code, Message: problem.message, Action: problem.action},
		})
	} else {
		_, _ = fmt.Fprintf(stderr, "wyrwood %s: %s. %s\n", command, problem.message, problem.action)
	}
	return problem.exitCode
}

func writeSuccess(stdout, stderr io.Writer, format outputFormat, command string, result any) int {
	var err error
	if format == outputJSON {
		err = writeJSON(stdout, successEnvelope{Version: 1, Command: command, OK: true, Result: result})
	} else {
		err = writeHuman(stdout, command, result)
	}
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "wyrwood: could not write command output")
		return exitOperational
	}
	return exitSuccess
}

func writeJSON(writer io.Writer, value any) error {
	encoder := json.NewEncoder(writer)
	return encoder.Encode(value)
}

func writeHuman(writer io.Writer, command string, result any) error {
	switch command {
	case "init":
		value := result.(initResult)
		_, err := fmt.Fprintf(writer, "Created configuration at %s.\n", strconv.Quote(value.Path))
		return err
	case "apply":
		value := result.(control.ApplyResult)
		_, err := fmt.Fprintf(writer, "Configuration applied (degraded=%t, pending-cleanup=%d, pending-permissions=%d).\n", value.Degraded, value.PendingCleanup, value.PendingPermissions)
		return err
	case "keys":
		return writeKeys(writer, result.(control.KeysResult))
	case "status":
		return writeStatus(writer, result.(control.StatusResult))
	case "events":
		return writeEvents(writer, result.(control.EventsResult))
	case "service":
		value := result.(userservice.Result)
		_, err := fmt.Fprintf(writer, "Service %s: installed=%t, enabled=%t, state=%s.\n", value.Action, value.Installed, value.Enabled, value.State)
		return err
	default:
		return errors.New("unknown human output projection")
	}
}

func writeKeys(writer io.Writer, result control.KeysResult) error {
	if len(result.Keys) == 0 {
		_, err := io.WriteString(writer, "No upstream keys are available.\n")
		return err
	}
	if _, err := io.WriteString(writer, "FINGERPRINT\tDISPLAY\n"); err != nil {
		return err
	}
	for _, key := range result.Keys {
		if _, err := fmt.Fprintf(writer, "%s\t%s\n", key.Fingerprint, strconv.Quote(key.Display)); err != nil {
			return err
		}
	}
	return nil
}

func writeStatus(writer io.Writer, result control.StatusResult) error {
	if _, err := fmt.Fprintf(writer, "Daemon: %s\nUpstream: %s\nConsumers: %d\nTruncated: %t\n", result.Daemon, result.Upstream, len(result.Consumers), result.Truncated); err != nil {
		return err
	}
	if len(result.Consumers) == 0 {
		return nil
	}
	if _, err := io.WriteString(writer, "ID\tNAME\tLISTENER\tCONNECTIONS\n"); err != nil {
		return err
	}
	for _, consumer := range result.Consumers {
		if _, err := fmt.Fprintf(writer, "%s\t%s\t%s\t%d\n", strconv.Quote(consumer.ID), strconv.Quote(consumer.Name), consumer.Listener, consumer.ActiveConnections); err != nil {
			return err
		}
	}
	return nil
}

func writeEvents(writer io.Writer, result control.EventsResult) error {
	if len(result.Events) == 0 {
		_, err := io.WriteString(writer, "No operational events are retained.\n")
		return err
	}
	if _, err := io.WriteString(writer, "TIMESTAMP\tCONSUMER\tOPERATION\tFINGERPRINT\tOUTCOME\tLATENCY_NS\tERROR\n"); err != nil {
		return err
	}
	for _, event := range result.Events {
		fingerprint := "-"
		if event.Fingerprint != nil {
			fingerprint = *event.Fingerprint
		}
		if _, err := fmt.Fprintf(writer, "%s\t%s\t%s\t%s\t%s\t%d\t%s\n",
			event.Timestamp.Format(time.RFC3339Nano), strconv.Quote(event.ConsumerID), event.Operation,
			fingerprint, event.Outcome, event.LatencyNS, event.ErrorCode); err != nil {
			return err
		}
	}
	return nil
}
