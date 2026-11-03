// ---
// relationships:
//   implements: command-line-interface
//   uses: operator-interface
// ---

package command

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/wyrd-company/wyrwood/operator"
)

const operatorHelp = "Usage: wyrwood operator login|whoami, wyrwood policy put|get|list, wyrwood bind, wyrwood binding list|get, wyrwood unbind. See 'wyrwood help'.\n"

// runOperatorCommand is the command layer over the operator package: it parses
// arguments, calls one package function, and projects the result.
func runOperatorCommand(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	switch args[0] {
	case "operator":
		return runOperator(ctx, args[1:], stdin, stdout, stderr)
	case "policy":
		return runPolicy(ctx, args[1:], stdin, stdout, stderr)
	case "binding":
		return runBinding(ctx, args[1:], stdout, stderr)
	case "bind":
		return runBind(ctx, args[1:], stdout, stderr)
	default:
		return runUnbind(ctx, args[1:], stdout, stderr)
	}
}

func profilePath(selected options) (string, error) {
	if selected.config != "" {
		return selected.config, nil
	}
	return operator.DefaultProfilePath()
}

// connect opens the saved login. It writes the failure itself, and reports the
// exit status when it fails.
func connect(ctx context.Context, selected options, stderr io.Writer, name string) (*operator.Client, int) {
	path, err := profilePath(selected)
	if err != nil {
		return nil, writeFailure(stderr, selected.output, name, failureOperatorState)
	}
	profile, err := operator.LoadProfile(path)
	if err != nil {
		return nil, writeFailure(stderr, selected.output, name, failureOperatorState)
	}
	client, err := profile.Dial(ctx)
	if err != nil {
		return nil, writeOperatorFailure(stderr, selected.output, name, err)
	}
	return client, exitSuccess
}

func writeOperatorFailure(stderr io.Writer, format outputFormat, name string, err error) int {
	var reported *operator.Error
	if errors.As(err, &reported) {
		problem := failure{string(reported.Code), reported.Message, exitOperational}
		switch reported.Code {
		case operator.CodeNotApproved:
			problem = failureKeyNotApproved
		case operator.CodeOutsideGrant:
			problem.status = exitOutsideGrant
		case operator.CodeNotFound:
			problem.status = exitNotFound
		case operator.CodeBindingDiffer:
			problem.status = exitDiffers
		case operator.CodeInvalid:
			problem.status = exitUsage
		}
		if format == outputJSON {
			_ = json.NewEncoder(stderr).Encode(failureProjection{Version: outputVersion, Command: name, Error: problem.code, Message: problem.message})
			return problem.status
		}
		return writeFailure(stderr, format, name, problem)
	}
	return writeFailure(stderr, format, name, operatorFailure(err))
}

func operatorFailure(err error) failure {
	switch {
	case errors.Is(err, operator.ErrInvalidURL), errors.Is(err, operator.ErrInvalid):
		return failureUsage
	case errors.Is(err, operator.ErrLoginState):
		return failureOperatorState
	case errors.Is(err, operator.ErrKeySelection):
		return failureKeySelection
	case errors.Is(err, operator.ErrUnreachable):
		return failureUnreachable
	case errors.Is(err, operator.ErrHostKeyMismatch):
		return failureHostKey
	case errors.Is(err, operator.ErrHostKeyNotAccepted):
		return failureNotAccepted
	case errors.Is(err, operator.ErrNotApproved):
		return failureKeyNotApproved
	default:
		return failureOperational
	}
}

type operatorLoginProjection struct {
	Version               int    `json:"version"`
	KeyFingerprint        string `json:"key-fingerprint"`
	ControllerFingerprint string `json:"controller-fingerprint"`
	Status                string `json:"status"`
}

func runOperator(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		return writeFailure(stderr, outputHuman, "operator", failureUsage)
	}
	switch args[0] {
	case "login":
		return runOperatorLogin(ctx, args[1:], stdin, stdout, stderr)
	case "whoami":
		selected, positional, problem := parseOptions(args[1:], optionOutput|optionConfig)
		if selected.help {
			_, _ = io.WriteString(stdout, "Usage: wyrwood operator whoami [--config PATH] [--output human|json]\n")
			return exitSuccess
		}
		if problem != nil || len(positional) != 0 {
			return writeFailure(stderr, selected.output, "operator whoami", failureUsage)
		}
		client, status := connect(ctx, selected, stderr, "operator whoami")
		if client == nil {
			return status
		}
		defer client.Close()
		identity, err := client.Whoami(ctx)
		if err != nil {
			return writeOperatorFailure(stderr, selected.output, "operator whoami", err)
		}
		if selected.output == outputJSON {
			return writeJSON(stdout, struct {
				Version int `json:"version"`
				operator.Identity
			}{outputVersion, identity})
		}
		actions := make([]string, 0, len(identity.Grant.Actions))
		for _, action := range identity.Grant.Actions {
			actions = append(actions, string(action))
		}
		_, _ = fmt.Fprintf(stdout, "Label:    %s\nKey:      %s\nAgents:   %s\nPolicies: %s\nActions:  %s\n", identity.Label, identity.Fingerprint,
			dash(strings.Join(identity.Grant.Agents, ", ")), dash(strings.Join(identity.Grant.Policies, ", ")), dash(strings.Join(actions, ", ")))
		return exitSuccess
	case "-h", "--help":
		_, _ = io.WriteString(stdout, operatorHelp)
		return exitSuccess
	default:
		return writeFailure(stderr, outputHuman, "operator", failureUsage)
	}
}

var labelUnsafe = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// defaultLabel proposes this machine's name for a pending key.
func defaultLabel() string {
	hostname, err := os.Hostname()
	if err != nil {
		return ""
	}
	label := strings.TrimLeft(labelUnsafe.ReplaceAllString(hostname, "-"), "._-")
	if len(label) > 64 {
		label = label[:64]
	}
	if !operator.ValidLabel(label) {
		return ""
	}
	return label
}

func runOperatorLogin(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	name := "operator login"
	selected, positional, problem := parseOptions(args, optionOutput|optionConfig|optionAcceptFingerprint|optionKeyFile|optionAgentKey|optionLabel)
	if selected.help {
		_, _ = io.WriteString(stdout, "Usage: wyrwood operator login <ssh://host:port> [--key-file PATH | --agent-key SELECTION] [--label NAME] [--accept-fingerprint SHA256:...] [--config PATH] [--output human|json]\n")
		return exitSuccess
	}
	keyFile, agentKey, label := selected.text("--key-file"), selected.text("--agent-key"), selected.text("--label")
	if problem != nil || len(positional) != 1 || (keyFile != "" && agentKey != "") || (label != "" && !operator.ValidLabel(label)) {
		return writeFailure(stderr, selected.output, name, failureUsage)
	}
	path, err := profilePath(selected)
	if err != nil {
		return writeFailure(stderr, selected.output, name, failureOperatorState)
	}
	if label == "" {
		if _, loadErr := operator.LoadProfile(path); loadErr != nil {
			label = defaultLabel()
		}
	}
	input := bufio.NewReader(stdin)
	result, err := operator.LoginProfile(ctx, path, operator.LoginOptions{
		URL: positional[0], KeyFile: keyFile, AgentKey: agentKey, Label: label, AcceptFingerprint: selected.acceptFingerprint,
		Announce: func(fingerprint string) {
			if selected.output == outputHuman {
				_, _ = fmt.Fprintf(stdout, "Operator key: %s\n", fingerprint)
			}
		},
		Accept: func(fingerprint string) bool {
			_, _ = fmt.Fprintf(stderr, "Controller host key: %s\nCompare it with the web interface or 'wyrwood controller host-key'.\nAccept this controller? [y/N] ", fingerprint)
			answer, _ := input.ReadString('\n')
			answer = strings.ToLower(strings.TrimSpace(answer))
			return answer == "y" || answer == "yes"
		},
	})
	if err != nil {
		return writeOperatorFailure(stderr, selected.output, name, err)
	}
	status, exit := "pending", exitNotApproved
	if result.Approved {
		status, exit = "approved", exitSuccess
	}
	if selected.output == outputJSON {
		_ = writeJSON(stdout, operatorLoginProjection{outputVersion, result.KeyFingerprint, result.HostKey, status})
		return exit
	}
	_, _ = fmt.Fprintf(stdout, "Controller host key: %s\nStatus: %s\n", result.HostKey, status)
	if !result.Approved {
		_, _ = fmt.Fprintln(stdout, "Approve this key on the Operator keys screen of the controller web interface, and set its grant.")
	}
	return exit
}

type policyProjection struct {
	Version int             `json:"version"`
	Policy  operator.Policy `json:"policy"`
}

type policiesProjection struct {
	Version  int               `json:"version"`
	Policies []operator.Policy `json:"policies"`
}

func runPolicy(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		return writeFailure(stderr, outputHuman, "policy", failureUsage)
	}
	name := "policy " + args[0]
	var allowed optionSet
	var wanted int
	switch args[0] {
	case "put":
		allowed, wanted = optionFile|optionTransitKey|optionCARole, 1
	case "get":
		wanted = 1
	case "list":
	case "-h", "--help":
		_, _ = io.WriteString(stdout, operatorHelp)
		return exitSuccess
	default:
		return writeFailure(stderr, outputHuman, "policy", failureUsage)
	}
	selected, positional, problem := parseOptions(args[1:], allowed|optionOutput|optionConfig)
	if selected.help {
		_, _ = io.WriteString(stdout, operatorHelp)
		return exitSuccess
	}
	if problem != nil || len(positional) != wanted || (args[0] == "put" && selected.text("--file") == "") {
		return writeFailure(stderr, selected.output, name, failureUsage)
	}
	var put operator.PolicyPut
	if args[0] == "put" {
		source, err := readPolicySource(selected.text("--file"), stdin)
		if err != nil {
			return writeFailure(stderr, selected.output, name, failureOperational)
		}
		put = operator.PolicyPut{Name: positional[0], HCL: source}
		if selected.strings["--transit-key"] != nil || selected.strings["--ca-role"] != nil {
			put.SSH = &operator.PolicySSH{TransitKeys: selected.strings["--transit-key"], CARoles: selected.strings["--ca-role"]}
		}
	}
	client, status := connect(ctx, selected, stderr, name)
	if client == nil {
		return status
	}
	defer client.Close()
	if args[0] == "list" {
		policies, err := client.ListPolicies(ctx)
		if err != nil {
			return writeOperatorFailure(stderr, selected.output, name, err)
		}
		if selected.output == outputJSON {
			return writeJSON(stdout, policiesProjection{outputVersion, policies})
		}
		writePolicies(stdout, policies)
		return exitSuccess
	}
	var result operator.Policy
	var err error
	if args[0] == "put" {
		result, err = client.PutPolicy(ctx, put)
	} else {
		result, err = client.GetPolicy(ctx, positional[0])
	}
	if err != nil {
		return writeOperatorFailure(stderr, selected.output, name, err)
	}
	if selected.output == outputJSON {
		return writeJSON(stdout, policyProjection{outputVersion, result})
	}
	if args[0] == "put" {
		_, _ = fmt.Fprintf(stdout, "Policy %s is at revision %d.\n", result.Name, result.Revision)
		return exitSuccess
	}
	_, _ = fmt.Fprintf(stdout, "Policy:   %s\nRevision: %d\nValues:   %s\n\n%s\n", result.Name, result.Revision, dash(strings.Join(result.ValueNames, ", ")), result.HCL)
	return exitSuccess
}

const maximumPolicySourceBytes = 1 << 20

func readPolicySource(path string, stdin io.Reader) (string, error) {
	var reader io.Reader = stdin
	if path != "-" {
		file, err := os.Open(path)
		if err != nil {
			return "", err
		}
		defer file.Close()
		reader = file
	}
	data, err := io.ReadAll(io.LimitReader(reader, maximumPolicySourceBytes))
	return string(data), err
}

func writePolicies(output io.Writer, policies []operator.Policy) {
	if len(policies) == 0 {
		_, _ = fmt.Fprintln(output, "No policies inside this key's grant.")
		return
	}
	rows := [][]string{{"NAME", "REVISION", "VALUES"}}
	for _, item := range policies {
		rows = append(rows, []string{item.Name, strconv.Itoa(item.Revision), dash(strings.Join(item.ValueNames, ", "))})
	}
	writeTable(output, rows)
}

type bindingProjection struct {
	Version int              `json:"version"`
	Binding operator.Binding `json:"binding"`
}

type bindingsProjection struct {
	Version  int                `json:"version"`
	Bindings []operator.Binding `json:"bindings"`
}

func runBind(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	name := "bind"
	selected, positional, problem := parseOptions(args, optionOutput|optionConfig|optionAgent|optionKey|optionPolicy|optionAccessGroup|optionValue|optionTokenTTL|optionTokenMaxTTL|optionEnforcement)
	if selected.help {
		_, _ = io.WriteString(stdout, operatorHelp)
		return exitSuccess
	}
	if problem != nil || len(positional) != 0 || selected.text("--agent") == "" || len(selected.strings["--policy"]) == 0 {
		return writeFailure(stderr, selected.output, name, failureUsage)
	}
	key, err := operator.ParseKey(selected.text("--key"))
	if err != nil {
		return writeFailure(stderr, selected.output, name, failureUsage)
	}
	settings := operator.Settings{TokenTTL: selected.text("--token-ttl"), TokenMaxTTL: selected.text("--token-max-ttl"), Enforcement: selected.text("--enforcement")}
	if text := selected.text("--access-group"); text != "" {
		group, err := strconv.ParseUint(text, 10, 32)
		if err != nil {
			return writeFailure(stderr, selected.output, name, failureUsage)
		}
		value := uint32(group)
		settings.AccessGroup = &value
	}
	for _, pair := range selected.strings["--value"] {
		valueName, value, found := strings.Cut(pair, "=")
		if !found || valueName == "" {
			return writeFailure(stderr, selected.output, name, failureUsage)
		}
		if settings.Values == nil {
			settings.Values = map[string]string{}
		}
		if _, repeated := settings.Values[valueName]; repeated {
			return writeFailure(stderr, selected.output, name, failureUsage)
		}
		settings.Values[valueName] = value
	}
	client, status := connect(ctx, selected, stderr, name)
	if client == nil {
		return status
	}
	defer client.Close()
	bound, err := client.Bind(ctx, operator.BindRequest{Agent: selected.text("--agent"), Key: key, Policies: selected.strings["--policy"], Settings: settings})
	if err != nil {
		return writeOperatorFailure(stderr, selected.output, name, err)
	}
	if selected.output == outputJSON {
		return writeJSON(stdout, bindingProjection{outputVersion, bound})
	}
	writeBinding(stdout, bound)
	return exitSuccess
}

func runBinding(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		return writeFailure(stderr, outputHuman, "binding", failureUsage)
	}
	name := "binding " + args[0]
	var allowed optionSet
	var wanted int
	switch args[0] {
	case "list":
		allowed = optionAgent
	case "get":
		wanted = 1
	case "-h", "--help":
		_, _ = io.WriteString(stdout, operatorHelp)
		return exitSuccess
	default:
		return writeFailure(stderr, outputHuman, "binding", failureUsage)
	}
	selected, positional, problem := parseOptions(args[1:], allowed|optionOutput|optionConfig)
	if selected.help {
		_, _ = io.WriteString(stdout, operatorHelp)
		return exitSuccess
	}
	if problem != nil || len(positional) != wanted {
		return writeFailure(stderr, selected.output, name, failureUsage)
	}
	client, status := connect(ctx, selected, stderr, name)
	if client == nil {
		return status
	}
	defer client.Close()
	if args[0] == "get" {
		result, err := client.GetBinding(ctx, positional[0])
		if err != nil {
			return writeOperatorFailure(stderr, selected.output, name, err)
		}
		if selected.output == outputJSON {
			return writeJSON(stdout, bindingProjection{outputVersion, result})
		}
		writeBinding(stdout, result)
		return exitSuccess
	}
	bindings, err := client.ListBindings(ctx, operator.BindingList{Agent: selected.text("--agent")})
	if err != nil {
		return writeOperatorFailure(stderr, selected.output, name, err)
	}
	if selected.output == outputJSON {
		return writeJSON(stdout, bindingsProjection{outputVersion, bindings})
	}
	if len(bindings) == 0 {
		_, _ = fmt.Fprintln(stdout, "No bindings inside this key's grant.")
		return exitSuccess
	}
	rows := [][]string{{"ID", "AGENT", "KEY", "POLICIES", "READINESS", "REASONS"}}
	for _, item := range bindings {
		rows = append(rows, []string{item.ID, item.Agent, string(item.Key.Kind) + ":" + item.Key.Value, strings.Join(item.Policies, ", "),
			string(item.Status.Readiness), dash(strings.Join(item.Status.Reasons, ", "))})
	}
	writeTable(stdout, rows)
	return exitSuccess
}

func writeBinding(output io.Writer, binding operator.Binding) {
	_, _ = fmt.Fprintf(output, "Binding:   %s\nAgent:     %s\nKey:       %s:%s\nPolicies:  %s\nReadiness: %s\n", binding.ID, binding.Agent,
		binding.Key.Kind, binding.Key.Value, strings.Join(binding.Policies, ", "), binding.Status.Readiness)
	if len(binding.Status.Reasons) > 0 {
		_, _ = fmt.Fprintf(output, "Reasons:   %s\n", strings.Join(binding.Status.Reasons, ", "))
	}
}

type unbindProjection struct {
	Version int `json:"version"`
	operator.UnbindResult
}

func runUnbind(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	name := "unbind"
	selected, positional, problem := parseOptions(args, optionOutput|optionConfig|optionAgent|optionKey)
	if selected.help {
		_, _ = io.WriteString(stdout, operatorHelp)
		return exitSuccess
	}
	if problem != nil || len(positional) > 1 {
		return writeFailure(stderr, selected.output, name, failureUsage)
	}
	request := operator.UnbindRequest{Agent: selected.text("--agent")}
	if len(positional) == 1 {
		if request.Agent != "" || selected.text("--key") != "" {
			return writeFailure(stderr, selected.output, name, failureUsage)
		}
		request.ID = positional[0]
	} else {
		key, err := operator.ParseKey(selected.text("--key"))
		if err != nil || request.Agent == "" {
			return writeFailure(stderr, selected.output, name, failureUsage)
		}
		request.Key = &key
	}
	client, status := connect(ctx, selected, stderr, name)
	if client == nil {
		return status
	}
	defer client.Close()
	result, err := client.Unbind(ctx, request)
	if err != nil {
		return writeOperatorFailure(stderr, selected.output, name, err)
	}
	if selected.output == outputJSON {
		return writeJSON(stdout, unbindProjection{outputVersion, result})
	}
	if result.Removed {
		_, _ = fmt.Fprintln(stdout, "Binding removed.")
	} else {
		_, _ = fmt.Fprintln(stdout, "No such binding; nothing to remove.")
	}
	if result.Warning != "" {
		_, _ = fmt.Fprintf(stderr, "Warning: %s\n", result.Warning)
	}
	return exitSuccess
}
