// ---
// relationships:
//   implements: command-line-interface
//   uses: agent
// ---

package command

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/wyrd-company/wyrwood/internal/agent"
	"github.com/wyrd-company/wyrwood/internal/config"
)

const controlTimeout = 5 * time.Second

func runAgent(args []string, stdin io.Reader, stdout, stderr io.Writer, deps dependencies) int {
	if len(args) == 0 {
		return writeFailure(stderr, outputHuman, "agent", failureUsage)
	}
	name := "agent " + args[0]
	switch args[0] {
	case "login":
		return runAgentLogin(args[1:], stdin, stdout, stderr, deps)
	case "engine-proxy":
		options, positional, problem := parseOptions(args[1:], optionConfig)
		if options.help {
			_, _ = io.WriteString(stdout, "Usage: wyrwood agent engine-proxy [--config path]\n")
			return exitSuccess
		}
		if problem != nil || len(positional) != 0 {
			return writeFailure(stderr, outputHuman, name, failureUsage)
		}
		path := options.config
		if path == "" {
			path = config.DefaultAgentPath
		}
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		if err := deps.runEngineProxy(ctx, path); err != nil {
			return writeFailure(stderr, outputHuman, name, failureOperational)
		}
		return exitSuccess
	case "daemon":
		options, positional, problem := parseOptions(args[1:], 0)
		if options.help {
			_, _ = io.WriteString(stdout, "Usage: wyrwood agent daemon\n")
			return exitSuccess
		}
		if problem != nil || len(positional) != 0 {
			return writeFailure(stderr, outputHuman, name, failureUsage)
		}
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		if err := deps.runAgent(ctx); err != nil {
			if errors.Is(err, errConfiguration) {
				return writeFailure(stderr, outputHuman, name, failureConfiguration)
			}
			return writeFailure(stderr, outputHuman, name, failureOperational)
		}
		return exitSuccess
	case "status", "containers", "events":
		allowed := optionOutput
		if args[0] == "events" {
			allowed |= optionLimit
		}
		options, positional, problem := parseOptions(args[1:], allowed)
		if options.help {
			_, _ = fmt.Fprintf(stdout, "Usage: wyrwood agent %s [--output human|json]\n", args[0])
			return exitSuccess
		}
		if problem != nil || len(positional) != 0 {
			return writeFailure(stderr, options.output, name, failureUsage)
		}
		return runAgentQuery(args[0], options, stdout, stderr, deps)
	case "service":
		return runService(args[1:], stdout, stderr, deps)
	default:
		return writeFailure(stderr, outputHuman, "agent", failureUsage)
	}
}

type loginProjection struct {
	Version               int    `json:"version"`
	AgentFingerprint      string `json:"agent-fingerprint"`
	ControllerFingerprint string `json:"controller-fingerprint"`
	Status                string `json:"status"`
}

func runAgentLogin(args []string, stdin io.Reader, stdout, stderr io.Writer, deps dependencies) int {
	name := "agent login"
	options, positional, problem := parseOptions(args, optionOutput|optionAcceptFingerprint)
	if options.help {
		_, _ = io.WriteString(stdout, "Usage: wyrwood agent login <ssh://host:port> [--accept-fingerprint SHA256:...] [--output human|json]\n")
		return exitSuccess
	}
	if problem != nil || len(positional) != 1 {
		return writeFailure(stderr, options.output, name, failureUsage)
	}
	input := bufio.NewReader(stdin)
	loginOptions := agent.LoginOptions{
		ControllerURL:     positional[0],
		AcceptFingerprint: options.acceptFingerprint,
		Announce: func(fingerprint string) {
			if options.output == outputHuman {
				_, _ = fmt.Fprintf(stdout, "Agent key: %s\n", fingerprint)
			}
		},
		Confirm: func(fingerprint string) bool {
			_, _ = fmt.Fprintf(stderr, "Controller host key: %s\nCompare it with the web interface or 'wyrwood controller host-key'.\nAccept this controller? [y/N] ", fingerprint)
			answer, _ := input.ReadString('\n')
			answer = strings.ToLower(strings.TrimSpace(answer))
			return answer == "y" || answer == "yes"
		},
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	result, err := deps.agentLogin(ctx, loginOptions)
	if err != nil {
		return writeFailure(stderr, options.output, name, loginFailure(err))
	}
	status, exit := "pending", exitNotApproved
	if result.Approved {
		status, exit = "approved", exitSuccess
	}
	if options.output == outputJSON {
		_ = writeJSON(stdout, loginProjection{outputVersion, result.AgentFingerprint, result.ControllerFingerprint, status})
		return exit
	}
	_, _ = fmt.Fprintf(stdout, "Controller host key: %s\nStatus: %s\n", result.ControllerFingerprint, status)
	if !result.Approved {
		_, _ = fmt.Fprintln(stdout, "Approve this agent's key in the controller web interface, then start the agent.")
	}
	return exit
}

func loginFailure(err error) failure {
	switch {
	case errors.Is(err, agent.ErrInvalidURL):
		return failureUsage
	case errors.Is(err, agent.ErrLoginState):
		return failureLoginState
	case errors.Is(err, agent.ErrUnreachable):
		return failureUnreachable
	case errors.Is(err, agent.ErrHostKeyMismatch):
		return failureHostKey
	case errors.Is(err, agent.ErrNotAccepted):
		return failureNotAccepted
	default:
		return failureOperational
	}
}

func runAgentQuery(operation string, options options, stdout, stderr io.Writer, deps dependencies) int {
	name := "agent " + operation
	ctx, cancel := context.WithTimeout(context.Background(), controlTimeout)
	defer cancel()
	request := agent.ControlRequest{Operation: operation}
	if operation == "events" {
		request.Limit = options.limit
	}
	var err error
	switch operation {
	case "status":
		var status agent.Status
		if err = deps.queryAgent(ctx, request, &status); err == nil {
			if options.output == outputJSON {
				return writeJSON(stdout, status)
			}
			writeStatus(stdout, status)
		}
	case "containers":
		var containers agent.Containers
		if err = deps.queryAgent(ctx, request, &containers); err == nil {
			if options.output == outputJSON {
				return writeJSON(stdout, containers)
			}
			writeContainers(stdout, containers)
		}
	case "events":
		var history agent.Events
		if err = deps.queryAgent(ctx, request, &history); err == nil {
			if options.output == outputJSON {
				return writeJSON(stdout, history)
			}
			writeEvents(stdout, history)
		}
	}
	if err != nil {
		return writeFailure(stderr, options.output, name, failureDaemon)
	}
	return exitSuccess
}

func writeStatus(output io.Writer, status agent.Status) {
	_, _ = fmt.Fprintf(output, "Agent:       %s\n", status.Agent)
	_, _ = fmt.Fprintf(output, "Controller:  %s (%s)\n", status.Controller, status.Session)
	_, _ = fmt.Fprintf(output, "Containers:  %d\n", status.Containers)
	_, _ = fmt.Fprintf(output, "Bindings:    %d\n", status.Bindings)
	_, _ = fmt.Fprintf(output, "Tokens:      %d\n", status.Tokens)
	categories := make([]string, 0, len(status.Health))
	for category := range status.Health {
		categories = append(categories, category)
	}
	sort.Strings(categories)
	parts := make([]string, 0, len(categories))
	for _, category := range categories {
		parts = append(parts, fmt.Sprintf("%s %d", category, status.Health[category]))
	}
	if len(parts) == 0 {
		parts = append(parts, "unknown")
	}
	_, _ = fmt.Fprintf(output, "Health:      %s\n", strings.Join(parts, ", "))
}

func writeContainers(output io.Writer, containers agent.Containers) {
	if len(containers.Containers) == 0 {
		_, _ = fmt.Fprintln(output, "No containers observed.")
		return
	}
	rows := [][]string{{"NAME", "STATE", "KEY", "POLICY", "CONFORMANCE", "TOKEN", "FAILED ITEMS", "ACCESS GROUP ERROR"}}
	for _, container := range containers.Containers {
		var failed []string
		for _, item := range container.FailedItems {
			failed = append(failed, string(item))
		}
		rows = append(rows, []string{container.Name, container.State, dash(container.BindingKey), dash(strings.Join(container.Policies, ", ")), container.Conformance, container.Token, dash(strings.Join(failed, ", ")), dash(container.AccessGroupError)})
	}
	writeTable(output, rows)
}

func writeEvents(output io.Writer, history agent.Events) {
	if len(history.Events) == 0 {
		_, _ = fmt.Fprintln(output, "No events recorded.")
		return
	}
	rows := [][]string{{"TIME", "OPERATION", "OUTCOME", "ERROR", "SUBJECT", "LATENCY"}}
	for _, record := range history.Events {
		subject := record.ContainerKey
		if subject == "" {
			subject = record.Binding
		}
		if record.Mount != "" {
			subject = strings.TrimSpace(subject + " " + string(record.Method) + " " + string(record.Mount))
		}
		if record.Fingerprint != "" {
			subject = strings.TrimSpace(subject + " " + record.Fingerprint)
		}
		rows = append(rows, []string{record.Time, string(record.Operation), string(record.Outcome), dash(string(record.Error)),
			dash(subject), time.Duration(record.LatencyNS).Round(time.Microsecond).String()})
	}
	writeTable(output, rows)
}

func dash(value string) string {
	if value == "" {
		return "-"
	}
	return value
}

func writeTable(output io.Writer, rows [][]string) {
	widths := make([]int, len(rows[0]))
	for _, row := range rows {
		for index, cell := range row {
			if len(cell) > widths[index] {
				widths[index] = len(cell)
			}
		}
	}
	for _, row := range rows {
		cells := make([]string, len(row))
		for index, cell := range row {
			if index == len(row)-1 {
				cells[index] = cell
			} else {
				cells[index] = cell + strings.Repeat(" ", widths[index]-len(cell))
			}
		}
		_, _ = fmt.Fprintln(output, strings.Join(cells, "  "))
	}
}
