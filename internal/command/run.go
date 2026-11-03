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
  controller openbao-admin configure|remove
                                        Configure namespace OIDC secret access

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

Operator (policies and bindings over SSH):
  operator login <ssh://host:port> [--key-file PATH | --agent-key SELECTION]
                 [--label NAME] [--accept-fingerprint SHA256:...]
                                        Present a key and request approval
  operator whoami                       Print this key's label and grant
  policy put <name> --file PATH [--transit-key NAME]... [--ca-role NAME]...
                                        Create or change a policy from an HCL file
  policy get <name>                     Print one policy
  policy list                           List policies inside the grant
  bind --agent NAME --key KIND:VALUE --policy NAME [--policy NAME]...
       [--access-group GID] [--value NAME=VALUE]... [--token-ttl T]
       [--token-max-ttl T] [--enforcement report|recreate]
                                        Bind a container key; safe to repeat
  binding list [--agent NAME]           List bindings with their readiness
  binding get <id>                      Print one binding with its readiness
  unbind <id> | --agent NAME --key KIND:VALUE
                                        Remove a binding; safe to repeat
  These commands accept --config PATH to select the saved login.

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
		return runController(args[1:], stdin, stdout, stderr, deps)
	case "agent":
		return runAgent(args[1:], stdin, stdout, stderr, deps)
	case "operator", "policy", "binding", "bind", "unbind":
		return runOperatorCommand(args, stdin, stdout, stderr)
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
	optionKeyFile
	optionAgentKey
	optionLabel
	optionFile
	optionAgent
	optionKey
	optionPolicy
	optionAccessGroup
	optionValue
	optionTokenTTL
	optionTokenMaxTTL
	optionEnforcement
	optionTransitKey
	optionCARole
)

// stringOptions are the options that hold text, by flag, for the operator
// commands. Repeatable ones may occur more than once.
var stringOptions = map[string]struct {
	set        optionSet
	repeatable bool
}{
	"--key-file": {optionKeyFile, false}, "--agent-key": {optionAgentKey, false}, "--label": {optionLabel, false},
	"--file": {optionFile, false}, "--agent": {optionAgent, false}, "--key": {optionKey, false},
	"--policy": {optionPolicy, true}, "--access-group": {optionAccessGroup, false}, "--value": {optionValue, true},
	"--token-ttl": {optionTokenTTL, false}, "--token-max-ttl": {optionTokenMaxTTL, false}, "--enforcement": {optionEnforcement, false},
	"--transit-key": {optionTransitKey, true}, "--ca-role": {optionCARole, true},
}

type options struct {
	output            outputFormat
	config            string
	acceptFingerprint string
	limit             int
	help              bool
	strings           map[string][]string
}

// text returns a single-value string option, or the empty string.
func (result options) text(name string) string {
	if values := result.strings[name]; len(values) > 0 {
		return values[0]
	}
	return ""
}

// parseOptions parses the allowed options and returns positional arguments.
// The output format is resolved first so usage failures use the requested
// projection whenever it can be determined.
func parseOptions(args []string, allowed optionSet) (options, []string, *failure) {
	result := options{output: outputHuman, limit: 100, strings: map[string][]string{}}
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
		text, isText := stringOptions[name]
		if seen[name] && !(isText && text.repeatable) {
			return result, nil, &failureUsage
		}
		seen[name] = true
		switch {
		case isText && allowed&text.set != 0:
			result.strings[name] = append(result.strings[name], value)
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
