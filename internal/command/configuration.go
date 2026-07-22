//go:build linux

// ---
// relationships:
//   implements: command-line-interface
//   uses: control-interface
// ---

package command

import (
	"errors"
	"io"
	"strconv"
	"strings"

	"github.com/wyrd-company/wyrwood/internal/config"
	"github.com/wyrd-company/wyrwood/internal/control"
)

const configurationHelp = `Usage:
  wyrwood configuration show [--output human|json]
  wyrwood configuration set-upstream --revision REVISION --socket SOCKET [--output human|json]
  wyrwood configuration set-timeouts --revision REVISION --connect DURATION --list DURATION --replay DURATION --sign DURATION [--output human|json]
`

const consumerHelp = `Usage:
  wyrwood consumer put --revision REVISION [--id ID] --name NAME --socket SOCKET [--access-group GROUP] [--fingerprint FINGERPRINT]... [--output human|json]
  wyrwood consumer retire --revision REVISION --id ID [--output human|json]
`

type semanticOptions struct {
	output       outputFormat
	revision     string
	socket       string
	connect      string
	list         string
	replay       string
	sign         string
	id           string
	name         string
	accessGroup  *uint32
	fingerprints []string
}

func runConfiguration(args []string, stdout, stderr io.Writer, deps dependencies) int {
	if len(args) == 1 && isHelp(args[0]) {
		_, _ = io.WriteString(stdout, configurationHelp)
		return exitSuccess
	}
	if len(args) == 0 {
		return writeFailure(stderr, outputHuman, "configuration", failureUsage)
	}
	command := "configuration-" + args[0]
	switch args[0] {
	case "show":
		options, problem, help := parseSemanticOptions(args[1:], nil, nil)
		if help {
			_, _ = io.WriteString(stdout, "Usage: wyrwood configuration show [--output human|json]\n")
			return exitSuccess
		}
		if problem != nil {
			return writeFailure(stderr, options.output, command, *problem)
		}
		client, problem := resolveControlClient(deps)
		if problem != nil {
			return writeFailure(stderr, options.output, command, *problem)
		}
		result, err := loadConfiguration(client)
		if err != nil {
			return writeFailure(stderr, options.output, command, classifyRequestFailure(err))
		}
		return writeSuccess(stdout, stderr, options.output, command, result)
	case "set-upstream":
		return runSetUpstream(command, args[1:], stdout, stderr, deps)
	case "set-timeouts":
		return runSetTimeouts(command, args[1:], stdout, stderr, deps)
	default:
		return writeFailure(stderr, outputHuman, "configuration", failureUsage)
	}
}

func runConsumer(args []string, stdout, stderr io.Writer, deps dependencies) int {
	if len(args) == 1 && isHelp(args[0]) {
		_, _ = io.WriteString(stdout, consumerHelp)
		return exitSuccess
	}
	if len(args) == 0 {
		return writeFailure(stderr, outputHuman, "consumer", failureUsage)
	}
	command := "consumer-" + args[0]
	switch args[0] {
	case "put":
		return runPutConsumer(command, args[1:], stdout, stderr, deps)
	case "retire":
		return runRetireConsumer(command, args[1:], stdout, stderr, deps)
	default:
		return writeFailure(stderr, outputHuman, "consumer", failureUsage)
	}
}

func runSetUpstream(command string, args []string, stdout, stderr io.Writer, deps dependencies) int {
	options, problem, help := parseSemanticOptions(args, []string{"revision", "socket"}, []string{"revision", "socket"})
	if help {
		_, _ = io.WriteString(stdout, "Usage: wyrwood configuration set-upstream --revision REVISION --socket SOCKET [--output human|json]\n")
		return exitSuccess
	}
	if problem != nil {
		return writeFailure(stderr, options.output, command, *problem)
	}
	client, problem := resolveControlClient(deps)
	if problem != nil {
		return writeFailure(stderr, options.output, command, *problem)
	}
	result, err := client.SetUpstream(options.revision, options.socket)
	if err != nil {
		return writeFailure(stderr, options.output, command, classifyRequestFailure(err))
	}
	return writeSuccess(stdout, stderr, options.output, command, configurationChangeResult{Revision: result.Revision, Changed: result.Changed})
}

func runSetTimeouts(command string, args []string, stdout, stderr io.Writer, deps dependencies) int {
	fields := []string{"revision", "connect", "list", "replay", "sign"}
	options, problem, help := parseSemanticOptions(args, fields, fields)
	if help {
		_, _ = io.WriteString(stdout, "Usage: wyrwood configuration set-timeouts --revision REVISION --connect DURATION --list DURATION --replay DURATION --sign DURATION [--output human|json]\n")
		return exitSuccess
	}
	if problem != nil {
		return writeFailure(stderr, options.output, command, *problem)
	}
	client, problem := resolveControlClient(deps)
	if problem != nil {
		return writeFailure(stderr, options.output, command, *problem)
	}
	result, err := client.SetTimeouts(options.revision, control.ConfigurationTimeouts{Connect: options.connect, List: options.list, Replay: options.replay, Sign: options.sign})
	if err != nil {
		return writeFailure(stderr, options.output, command, classifyRequestFailure(err))
	}
	return writeSuccess(stdout, stderr, options.output, command, configurationChangeResult{Revision: result.Revision, Changed: result.Changed})
}

func runPutConsumer(command string, args []string, stdout, stderr io.Writer, deps dependencies) int {
	options, problem, help := parseSemanticOptions(args, []string{"revision", "id", "name", "socket", "access-group", "fingerprint"}, []string{"revision", "name", "socket"})
	if help {
		_, _ = io.WriteString(stdout, "Usage: wyrwood consumer put --revision REVISION [--id ID] --name NAME --socket SOCKET [--access-group GROUP] [--fingerprint FINGERPRINT]... [--output human|json]\n")
		return exitSuccess
	}
	if problem != nil {
		return writeFailure(stderr, options.output, command, *problem)
	}
	client, problem := resolveControlClient(deps)
	if problem != nil {
		return writeFailure(stderr, options.output, command, *problem)
	}
	var id *string
	if options.id != "" {
		id = &options.id
	}
	result, err := client.PutConsumer(options.revision, id, control.ConfigurationConsumerInput{
		Name: options.name, Socket: options.socket, AccessGroup: options.accessGroup, Fingerprints: options.fingerprints,
	})
	if err != nil {
		return writeFailure(stderr, options.output, command, classifyRequestFailure(err))
	}
	if result.ConsumerID == nil {
		return writeFailure(stderr, options.output, command, failureInvalidDaemonResponse)
	}
	return writeSuccess(stdout, stderr, options.output, command, consumerChangeResult{Revision: result.Revision, Changed: result.Changed, ConsumerID: *result.ConsumerID})
}

func runRetireConsumer(command string, args []string, stdout, stderr io.Writer, deps dependencies) int {
	fields := []string{"revision", "id"}
	options, problem, help := parseSemanticOptions(args, fields, fields)
	if help {
		_, _ = io.WriteString(stdout, "Usage: wyrwood consumer retire --revision REVISION --id ID [--output human|json]\n")
		return exitSuccess
	}
	if problem != nil {
		return writeFailure(stderr, options.output, command, *problem)
	}
	client, problem := resolveControlClient(deps)
	if problem != nil {
		return writeFailure(stderr, options.output, command, *problem)
	}
	result, err := client.RetireConsumer(options.revision, options.id)
	if err != nil {
		return writeFailure(stderr, options.output, command, classifyRequestFailure(err))
	}
	if result.ConsumerID == nil {
		return writeFailure(stderr, options.output, command, failureInvalidDaemonResponse)
	}
	return writeSuccess(stdout, stderr, options.output, command, consumerChangeResult{Revision: result.Revision, Changed: result.Changed, ConsumerID: *result.ConsumerID})
}

func resolveControlClient(deps dependencies) (controlClient, *failure) {
	path, err := deps.defaultControlPath()
	if err != nil {
		return nil, failurePointer(failureDaemonUnavailable)
	}
	client, err := deps.newClient(path)
	if err != nil {
		return nil, failurePointer(failureDaemonUnavailable)
	}
	return client, nil
}

func loadConfiguration(client controlClient) (configurationResult, error) {
	var result configurationResult
	offset := 0
	totalConsumers := -1
	previousSocket := ""
	for {
		page, err := client.Configuration(offset, control.MaximumConfigurationPageSize, result.Revision)
		if err != nil {
			return configurationResult{}, err
		}
		if offset == 0 {
			result.Revision, result.Upstream, result.Timeouts = page.Revision, page.Upstream, page.Timeouts
			totalConsumers = page.TotalConsumers
			result.Consumers = make([]configurationConsumer, 0)
		} else if page.Revision != result.Revision || page.Upstream != result.Upstream || page.Timeouts != result.Timeouts || page.TotalConsumers != totalConsumers {
			return configurationResult{}, errors.New("daemon returned incoherent configuration pages")
		}
		if page.Offset != offset || page.TotalConsumers < offset+len(page.Consumers) || page.Complete != (offset+len(page.Consumers) == page.TotalConsumers) || !page.Complete && len(page.Consumers) == 0 {
			return configurationResult{}, errors.New("daemon returned invalid configuration pagination")
		}
		for _, consumer := range page.Consumers {
			if previousSocket != "" && previousSocket >= consumer.Socket {
				return configurationResult{}, errors.New("daemon returned unordered configuration pages")
			}
			previousSocket = consumer.Socket
			result.Consumers = append(result.Consumers, configurationConsumer{
				ID: consumer.ID, Name: consumer.Name, Socket: consumer.Socket,
				AccessGroup: consumer.AccessGroup, Fingerprints: consumer.Fingerprints,
			})
		}
		offset += len(page.Consumers)
		if page.Complete {
			return result, nil
		}
	}
}

func parseSemanticOptions(args, allowed, required []string) (semanticOptions, *failure, bool) {
	options := semanticOptions{output: requestedOutput(args), fingerprints: make([]string, 0)}
	if len(args) == 1 && isHelp(args[0]) {
		return options, nil, true
	}
	allowedSet := map[string]bool{"output": true}
	for _, name := range allowed {
		allowedSet[name] = true
	}
	seen := make(map[string]bool)
	values := make(map[string][]string)
	for index := 0; index < len(args); index++ {
		name, value, hasValue := strings.Cut(args[index], "=")
		if !strings.HasPrefix(name, "--") || isHelp(name) {
			return options, failurePointer(failureUsage), false
		}
		name = strings.TrimPrefix(name, "--")
		if !allowedSet[name] || seen[name] && name != "fingerprint" {
			return options, failurePointer(failureUsage), false
		}
		if !hasValue {
			index++
			if index >= len(args) {
				return options, failurePointer(failureUsage), false
			}
			value = args[index]
		}
		if value == "" {
			return options, failurePointer(failureUsage), false
		}
		seen[name] = true
		values[name] = append(values[name], value)
	}
	for _, name := range required {
		if !seen[name] {
			return options, failurePointer(failureUsage), false
		}
	}
	if value := first(values["output"]); value != "" {
		if value != string(outputHuman) && value != string(outputJSON) {
			return options, failurePointer(failureUsage), false
		}
		options.output = outputFormat(value)
	}
	options.revision, options.socket, options.connect = first(values["revision"]), first(values["socket"]), first(values["connect"])
	options.list, options.replay, options.sign = first(values["list"]), first(values["replay"]), first(values["sign"])
	options.id, options.name = first(values["id"]), first(values["name"])
	if options.revision != "" && !isOpaqueIdentifier(options.revision) || options.id != "" && !isOpaqueIdentifier(options.id) {
		return options, failurePointer(failureUsage), false
	}
	if value := first(values["access-group"]); value != "" {
		parsed, err := strconv.ParseUint(value, 10, 32)
		if err != nil || parsed == 1<<32-1 {
			return options, failurePointer(failureUsage), false
		}
		group := uint32(parsed)
		options.accessGroup = &group
	}
	seenFingerprints := make(map[string]struct{})
	for _, fingerprint := range values["fingerprint"] {
		if _, duplicate := seenFingerprints[fingerprint]; duplicate {
			return options, failurePointer(failureUsage), false
		}
		seenFingerprints[fingerprint] = struct{}{}
		options.fingerprints = append(options.fingerprints, fingerprint)
	}
	if len(options.fingerprints) > config.MaximumFingerprintsPerConsumer {
		return options, failurePointer(failureUsage), false
	}
	return options, nil, false
}

func first(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func isHelp(value string) bool { return value == "--help" || value == "-h" }

func isOpaqueIdentifier(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' && character < 'a' || character > 'f' {
			return false
		}
	}
	return true
}
