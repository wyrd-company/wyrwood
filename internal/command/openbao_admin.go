// ---
// relationships:
//   implements:
//     - command-line-interface
//     - openbao-admin-access
// ---

package command

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/wyrd-company/wyrwood/internal/config"
	"github.com/wyrd-company/wyrwood/internal/openbao"
)

const adminUsage = `Usage:
  wyrwood controller openbao-admin configure [--config PATH] --token-file PATH
    --client-id ID --client-secret-stdin --kv-v2-mount MOUNT [--kv-v2-mount MOUNT]
    --token-ttl DURATION --token-max-ttl DURATION [--issuer URL] [--groups-claim KEY]
    [--output human|json]
  wyrwood controller openbao-admin remove [--config PATH] --token-file PATH
    [--output human|json]

A separate OpenBao namespace provisioning token is required. The controller
AppRole is never used. Pipe the separate OIDC client secret to stdin; never put
it in an argument or configuration. KV v2 mounts must already exist.
`

type adminCommandOptions struct {
	action, configPath, tokenFile, output, clientID, issuer, groupsClaim string
	mounts                                                               []string
	secretStdin, help                                                    bool
	ttl, maxTTL                                                          time.Duration
}

func parseAdminCommand(args []string) (adminCommandOptions, error) {
	result := adminCommandOptions{configPath: defaultControllerConfig, output: "human"}
	if len(args) == 0 || (args[0] != "configure" && args[0] != "remove") {
		return result, errors.New("usage")
	}
	result.action = args[0]
	fs := flag.NewFlagSet("openbao-admin", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&result.configPath, "config", defaultControllerConfig, "")
	fs.StringVar(&result.tokenFile, "token-file", "", "")
	fs.StringVar(&result.output, "output", "human", "")
	fs.BoolVar(&result.help, "help", false, "")
	fs.BoolVar(&result.help, "h", false, "")
	if result.action == "configure" {
		fs.StringVar(&result.clientID, "client-id", "", "")
		fs.StringVar(&result.issuer, "issuer", "", "")
		fs.StringVar(&result.groupsClaim, "groups-claim", "", "")
		fs.BoolVar(&result.secretStdin, "client-secret-stdin", false, "")
		fs.DurationVar(&result.ttl, "token-ttl", 0, "")
		fs.DurationVar(&result.maxTTL, "token-max-ttl", 0, "")
		fs.Func("kv-v2-mount", "", func(value string) error { result.mounts = append(result.mounts, value); return nil })
	}
	if err := fs.Parse(args[1:]); err != nil {
		return result, err
	}
	if result.help {
		return result, nil
	}
	invalidBlank := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name != "kv-v2-mount" && f.Value.String() == "" {
			invalidBlank = true
		}
	})
	if fs.NArg() != 0 || invalidBlank || result.configPath == "" || result.tokenFile == "" || (result.output != "human" && result.output != "json") ||
		(result.action == "configure" && (result.clientID == "" || !result.secretStdin || len(result.mounts) == 0 || result.ttl < time.Second || result.maxTTL < result.ttl)) {
		return result, errors.New("usage")
	}
	return result, nil
}

func runOpenBaoAdmin(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	// Resolve output before parsing so unknown options cannot echo their values.
	projection, _, _ := parseOptions(args, 0)
	options, err := parseAdminCommand(args)
	name := "controller openbao-admin"
	if options.action != "" {
		name += " " + options.action
	}
	if err != nil {
		return writeFailure(stderr, projection.output, name, failureUsage)
	}
	if options.help {
		_, _ = io.WriteString(stdout, adminUsage)
		return exitSuccess
	}
	format := outputFormat(options.output)
	cfg, err := config.LoadController(options.configPath)
	if err != nil {
		return writeFailure(stderr, format, name, failureConfiguration)
	}
	var settings openbao.AdminSettings
	if options.action == "configure" {
		issuer, groupsClaim := cfg.OIDC.Issuer, cfg.OIDC.GroupsClaim
		if options.issuer != "" {
			issuer = options.issuer
		}
		if options.groupsClaim != "" {
			groupsClaim = options.groupsClaim
		}
		settings = openbao.AdminSettings{Issuer: issuer, GroupsClaim: groupsClaim, ClientID: options.clientID,
			RedirectURL: cfg.OpenBao.UICallbackURL(), KVMounts: options.mounts, TokenTTL: options.ttl, TokenMaxTTL: options.maxTTL}
		if err := settings.Validate(); err != nil {
			return writeFailure(stderr, format, name, failureConfiguration)
		}
		if _, err := openbao.AdminPolicy(options.mounts); err != nil {
			return writeFailure(stderr, format, name, failureUsage)
		}
	}
	token, err := config.ReadSecretFile(options.tokenFile)
	if err != nil {
		return writeAdminFailure(stderr, format, name, "credential", openbao.CategoryInvalid, false)
	}
	client, err := openbao.NewAdminClient(openbao.Endpoint{Address: cfg.OpenBao.Address, CAFile: cfg.OpenBao.CAFile, Namespace: cfg.OpenBao.Namespace}, token)
	if err != nil {
		return writeFailure(stderr, format, name, failureConfiguration)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if options.action == "configure" {
		secret, err := readAdminSecret(stdin)
		if err != nil {
			return writeAdminFailure(stderr, format, name, "input", openbao.CategoryInvalid, false)
		}
		err = openbao.ConfigureAdmin(ctx, client, settings, secret)
		if err != nil {
			return adminCommandFailure(stderr, format, name, err)
		}
	} else if err := openbao.RemoveAdmin(ctx, client); err != nil {
		return adminCommandFailure(stderr, format, name, err)
	}
	if format == outputJSON {
		return writeJSON(stdout, struct {
			Version   int    `json:"version"`
			Action    string `json:"action"`
			Namespace string `json:"namespace"`
			AuthMount string `json:"auth-mount"`
			Role      string `json:"role"`
			Policy    string `json:"policy"`
		}{outputVersion, options.action, cfg.OpenBao.Namespace, openbao.AdminAuthMount, openbao.AdminRole, openbao.AdminPolicyName})
	}
	_, _ = fmt.Fprintf(stdout, "OpenBao admin access %s completed in namespace %s (auth %s, role %s, policy %s).\n", options.action, cfg.OpenBao.Namespace, openbao.AdminAuthMount, openbao.AdminRole, openbao.AdminPolicyName)
	return exitSuccess
}

func readAdminSecret(reader io.Reader) (string, error) {
	// The command consumes piped input only; it never asks a terminal to echo it.
	if file, ok := reader.(*os.File); ok {
		info, err := file.Stat()
		if err != nil || info.Mode()&os.ModeCharDevice != 0 {
			return "", errors.New("input")
		}
	}
	data, err := io.ReadAll(io.LimitReader(reader, (64<<10)+1))
	if err != nil || len(data) > 64<<10 {
		return "", errors.New("input")
	}
	secret := strings.TrimRight(string(data), "\r\n")
	if secret == "" || strings.ContainsAny(secret, "\r\n\x00") {
		return "", errors.New("input")
	}
	return secret, nil
}

func adminCommandFailure(stderr io.Writer, format outputFormat, name string, err error) int {
	var failure *openbao.AdminError
	if errors.As(err, &failure) {
		return writeAdminFailure(stderr, format, name, failure.Stage, failure.Category, failure.Partial)
	}
	return writeAdminFailure(stderr, format, name, "preflight", openbao.CategoryUnavailable, false)
}

func writeAdminFailure(stderr io.Writer, format outputFormat, name, stage string, category openbao.Category, partial bool) int {
	if format == outputJSON {
		_ = writeJSON(stderr, struct {
			Version int              `json:"version"`
			Command string           `json:"command"`
			Error   openbao.Category `json:"error"`
			Stage   string           `json:"stage"`
			Partial bool             `json:"partial"`
		}{outputVersion, name, category, stage, partial})
	} else {
		_, _ = fmt.Fprintf(stderr, "wyrwood %s: %s at %s (partial configuration: %t)\n", name, category, stage, partial)
	}
	return exitOperational
}
