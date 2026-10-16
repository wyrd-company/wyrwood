// ---
// relationships:
//   implements: command-line-interface
// ---

// Package command owns top-level command dispatch for the wyrwood executable.
package command

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

const help = `Wyrwood delivers OpenBao-backed secrets and signing to containers.

Usage:
  wyrwood <mode> <command> [options]

Controller:
  controller serve [--config PATH]      Run the controller
  controller host-key [--config PATH]   Print the controller SSH host-key fingerprint

Agent:
  agent login <ssh://host:port> [--accept-fingerprint SHA256:...]
                                        Create the agent key and request approval
  agent daemon                          Run the agent
  agent engine-proxy [--config PATH]     Run the filtering Engine boundary
  agent status                          Inspect agent, controller session, and binding health
  agent containers                      List observed containers and their bindings
  agent events [--limit N]              Inspect bounded operational events (1-1000, default 100)
  agent service install|remove|start|stop|status
                                        Manage the system unit (requires root)

Other:
  version                               Print the executable version
  help                                  Show this help

Options:
  --output human|json                   Select human output (default) or one JSON object
`

// version is replaced with the release version at link time.
var version = "dev"

// Version returns the executable version.
func Version() string { return version }

// Run executes the root command and returns a stable process exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	return run(args, os.Stdin, stdout, stderr, defaultDependencies())
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer, deps dependencies) int {
	if len(args) == 0 {
		_, _ = io.WriteString(stdout, help)
		return exitSuccess
	}
	switch args[0] {
	case "help", "-h", "--help":
		_, _ = io.WriteString(stdout, help)
		return exitSuccess
	case "version", "--version":
		options, positional, problem := parseOptions(args[1:], optionOutput)
		if problem != nil || len(positional) != 0 {
			return writeFailure(stderr, options.output, "version", failureUsage)
		}
		if options.output == outputJSON {
			return writeJSON(stdout, struct {
				Version int    `json:"version"`
				Wyrwood string `json:"wyrwood"`
			}{outputVersion, version})
		}
		_, _ = fmt.Fprintln(stdout, "wyrwood "+version)
		return exitSuccess
	case "controller":
		return runController(args[1:], stdout, stderr, deps)
	case "agent":
		return runAgent(args[1:], stdin, stdout, stderr, deps)
	default:
		_, _ = fmt.Fprintln(stderr, "unknown command")
		_, _ = fmt.Fprintln(stderr, "Run 'wyrwood help' for usage.")
		return exitUsage
	}
}

type optionSet uint

const (
	optionOutput optionSet = 1 << iota
	optionConfig
	optionAcceptFingerprint
	optionLimit
)

type options struct {
	output            outputFormat
	config            string
	acceptFingerprint string
	limit             int
	help              bool
}

// parseOptions parses the allowed options and returns positional arguments.
// The output format is resolved first so usage failures use the requested
// projection whenever it can be determined.
func parseOptions(args []string, allowed optionSet) (options, []string, *failure) {
	result := options{output: outputHuman, limit: 100}
	for index := 0; index < len(args); index++ {
		if args[index] == "--output" && index+1 < len(args) && args[index+1] == "json" {
			result.output = outputJSON
		}
		if args[index] == "--output=json" {
			result.output = outputJSON
		}
	}
	var positional []string
	seen := map[string]bool{}
	for index := 0; index < len(args); index++ {
		argument := args[index]
		if argument == "-h" || argument == "--help" {
			result.help = true
			continue
		}
		if !strings.HasPrefix(argument, "--") {
			positional = append(positional, argument)
			continue
		}
		name, value, inline := strings.Cut(argument, "=")
		if !inline {
			if index+1 >= len(args) {
				return result, nil, &failureUsage
			}
			index++
			value = args[index]
		}
		if seen[name] {
			return result, nil, &failureUsage
		}
		seen[name] = true
		switch {
		case name == "--output" && allowed&optionOutput != 0:
			switch value {
			case "human":
				result.output = outputHuman
			case "json":
				result.output = outputJSON
			default:
				return result, nil, &failureUsage
			}
		case name == "--config" && allowed&optionConfig != 0:
			if value == "" {
				return result, nil, &failureUsage
			}
			result.config = value
		case name == "--accept-fingerprint" && allowed&optionAcceptFingerprint != 0:
			result.acceptFingerprint = value
		case name == "--limit" && allowed&optionLimit != 0:
			limit, err := strconv.Atoi(value)
			if err != nil || limit < 1 || limit > 1000 {
				return result, nil, &failureUsage
			}
			result.limit = limit
		default:
			return result, nil, &failureUsage
		}
	}
	return result, positional, nil
}
