// ---
// relationships:
//   implements: command-line-interface
// ---

package command

import (
	"strconv"
	"strings"

	"github.com/wyrd-company/wyrwood/internal/control"
)

type outputFormat string

const (
	outputHuman       outputFormat = "human"
	outputJSON        outputFormat = "json"
	defaultEventLimit              = 100
)

type commandOptions struct {
	output     outputFormat
	eventLimit int
}

func parseCommandOptions(command string, args []string) (commandOptions, *failure, bool) {
	options := commandOptions{output: requestedOutput(args), eventLimit: defaultEventLimit}
	seenOutput, seenLimit := false, false
	for index := 0; index < len(args); index++ {
		name, value, hasValue := strings.Cut(args[index], "=")
		if name == "--help" || name == "-h" {
			if len(args) == 1 {
				return options, nil, true
			}
			return options, failurePointer(failureUsage), false
		}
		switch name {
		case "--output":
			if seenOutput {
				return options, failurePointer(failureUsage), false
			}
			seenOutput = true
			if !hasValue {
				index++
				if index >= len(args) {
					return options, failurePointer(failureUsage), false
				}
				value = args[index]
			}
			if value != string(outputHuman) && value != string(outputJSON) {
				return options, failurePointer(failureUsage), false
			}
			options.output = outputFormat(value)
		case "--limit":
			if command != "events" || seenLimit {
				return options, failurePointer(failureUsage), false
			}
			seenLimit = true
			if !hasValue {
				index++
				if index >= len(args) {
					return options, failurePointer(failureUsage), false
				}
				value = args[index]
			}
			limit, err := strconv.Atoi(value)
			if err != nil || limit < 1 || limit > control.MaximumEventLimit {
				return options, failurePointer(failureUsage), false
			}
			options.eventLimit = limit
		default:
			return options, failurePointer(failureUsage), false
		}
	}
	return options, nil, false
}

// requestedOutput lets an automation caller receive a structured usage error
// even when another option is malformed or appears before --output.
func requestedOutput(args []string) outputFormat {
	for index, argument := range args {
		if (argument == "--output" && index+1 < len(args) && args[index+1] == "json") || argument == "--output=json" {
			return outputJSON
		}
	}
	return outputHuman
}

func commandHelp(command string) string {
	if command == "service" {
		return "Usage: wyrwood service install|remove|start|stop|status [--output human|json]\n"
	}
	if command == "events" {
		return "Usage: wyrwood events [--limit NUMBER] [--output human|json]\n"
	}
	return "Usage: wyrwood " + command + " [--output human|json]\n"
}
