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
	exitSuccess                 = 0
	exitOperational             = 1
	exitUsage                   = 2
	exitInitialization          = 3
	exitDaemonUnavailable       = 4
	exitApplyInvalid            = 5
	exitRequestFailed           = 6
	exitUpstream                = 7
	exitConfigurationConflict   = 8
	exitConfigurationDurability = 9
	exitConfigurationNotFound   = 10
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

type configurationResult struct {
	Revision  string                        `json:"revision"`
	Upstream  string                        `json:"upstream"`
	Timeouts  control.ConfigurationTimeouts `json:"timeouts"`
	Consumers []configurationConsumer       `json:"consumers"`
}

type configurationConsumer struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Socket       string   `json:"socket"`
	AccessGroup  *uint32  `json:"access_group,omitempty"`
	Fingerprints []string `json:"fingerprints"`
}

type configurationChangeResult struct {
	Revision string `json:"revision"`
	Changed  bool   `json:"changed"`
}

type consumerChangeResult struct {
	Revision   string `json:"revision"`
	Changed    bool   `json:"changed"`
	ConsumerID string `json:"consumer_id"`
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
	failureServiceNotInstalled = failure{
		code: "service-not-installed", message: "the per-user service is not installed",
		action: "Run 'wyrwood service install' before retrying.", exitCode: exitOperational,
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
	case control.ErrorConfigurationInvalid:
		return failure{code: "configuration-invalid", message: "the configuration candidate was rejected", action: "Correct the complete candidate and retry from the current configuration revision.", exitCode: exitApplyInvalid}
	case control.ErrorConfigurationConflict:
		return failure{code: "configuration-conflict", message: "the configuration revision is stale", action: "Fetch the current configuration, reconcile the intended change, and retry with its revision.", exitCode: exitConfigurationConflict}
	case control.ErrorConfigurationNotFound:
		return failure{code: "configuration-not-found", message: "the selected consumer does not exist", action: "Fetch the current configuration and retry with an existing consumer identifier.", exitCode: exitConfigurationNotFound}
	case control.ErrorConfigurationFailed:
		return failure{code: "configuration-failed", message: "the configuration change could not be completed", action: "Inspect the current configuration before retrying.", exitCode: exitRequestFailed}
	case control.ErrorConfigurationDurabilityUncertain:
		return failure{code: "configuration-durability-uncertain", message: "the configuration was published, but its durability could not be confirmed", action: "Fetch the current configuration and inspect its revision before retrying.", exitCode: exitConfigurationDurability}
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
		_, _ = fmt.Fprintf(stderr, "wyrwood %s: %s. %s\n", humanCommand(command), problem.message, problem.action)
	}
	return problem.exitCode
}

func humanCommand(command string) string {
	switch command {
	case "configuration-show":
		return "configuration show"
	case "configuration-set-upstream":
		return "configuration set-upstream"
	case "configuration-set-timeouts":
		return "configuration set-timeouts"
	case "consumer-put":
		return "consumer put"
	case "consumer-retire":
		return "consumer retire"
	default:
		return command
	}
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
		_, err := fmt.Fprintf(writer, "Configuration applied at revision %s (committed=%t, degraded=%t, pending-cleanup=%d, pending-permissions=%d).\n", strconv.Quote(value.Revision), value.Committed, value.Degraded, value.PendingCleanup, value.PendingPermissions)
		return err
	case "keys":
		return writeKeys(writer, result.(control.KeysResult))
	case "status":
		return writeStatus(writer, result.(control.StatusResult))
	case "events":
		return writeEvents(writer, result.(control.EventsResult))
	case "configuration-show":
		return writeConfiguration(writer, result.(configurationResult))
	case "configuration-set-upstream", "configuration-set-timeouts":
		return writeConfigurationChange(writer, result.(configurationChangeResult), "")
	case "consumer-put", "consumer-retire":
		value := result.(consumerChangeResult)
		return writeConfigurationChange(writer, configurationChangeResult{Revision: value.Revision, Changed: value.Changed}, value.ConsumerID)
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
	observability := "complete"
	if result.Truncated {
		observability = "incomplete (status truncated)"
	}
	if _, err := fmt.Fprintf(writer, "Active revision: %s\nDaemon: %s\nUpstream: %s\nConsumers: %d\nRuntime observability: %s\n", strconv.Quote(result.ActiveRevision), result.Daemon, result.Upstream, len(result.Consumers), observability); err != nil {
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

func writeConfiguration(writer io.Writer, result configurationResult) error {
	if _, err := fmt.Fprintf(writer, "Revision: %s\nUpstream: %s\nTimeouts: connect=%s list=%s replay=%s sign=%s\nConsumers: %d\n",
		strconv.Quote(result.Revision), strconv.Quote(result.Upstream), strconv.Quote(result.Timeouts.Connect),
		strconv.Quote(result.Timeouts.List), strconv.Quote(result.Timeouts.Replay), strconv.Quote(result.Timeouts.Sign), len(result.Consumers)); err != nil {
		return err
	}
	for _, consumer := range result.Consumers {
		accessGroup := "-"
		if consumer.AccessGroup != nil {
			accessGroup = strconv.FormatUint(uint64(*consumer.AccessGroup), 10)
		}
		fingerprints := "["
		for index, fingerprint := range consumer.Fingerprints {
			if index > 0 {
				fingerprints += ","
			}
			fingerprints += strconv.Quote(fingerprint)
		}
		fingerprints += "]"
		if _, err := fmt.Fprintf(writer, "Consumer %s: name=%s socket=%s access-group=%s fingerprints=%s\n",
			strconv.Quote(consumer.ID), strconv.Quote(consumer.Name), strconv.Quote(consumer.Socket), accessGroup, fingerprints); err != nil {
			return err
		}
	}
	return nil
}

func writeConfigurationChange(writer io.Writer, result configurationChangeResult, consumerID string) error {
	if _, err := fmt.Fprintf(writer, "Configuration revision: %s\nChanged: %t\n", strconv.Quote(result.Revision), result.Changed); err != nil {
		return err
	}
	if consumerID != "" {
		_, err := fmt.Fprintf(writer, "Consumer: %s\n", strconv.Quote(consumerID))
		return err
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
