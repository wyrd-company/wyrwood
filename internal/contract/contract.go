// ---
// relationships:
//   implements: container-contract
//   uses: enforce-container-contracts-by-report-or-opt-in-recreate
// ---

// Package contract validates a bound container against its policy contract
// from inspect output and builds the create request that applies the
// contract when recreate is permitted.
package contract

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/wyrd-company/wyrwood/internal/engine"
	"github.com/wyrd-company/wyrwood/internal/policy"
	"github.com/wyrd-company/wyrwood/internal/protocol"
)

var anonymousVolumeName = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Check returns the failed contract items for a container whose consumer
// directory is consumerDirectory. canAssign reports whether the agent user
// can assign a group. Validation reads inspect output only.
func Check(container engine.Container, contract policy.Contract, consumerDirectory string, canAssign func(uint32) bool) []protocol.FailedItem {
	var failed []protocol.FailedItem
	mounted := false
	for _, mount := range container.Mounts {
		if mount.Type == "bind" && filepath.Clean(mount.Source) == filepath.Clean(consumerDirectory) &&
			filepath.Clean(mount.Destination) == contract.MountTarget {
			mounted = true
			break
		}
	}
	if !mounted {
		failed = append(failed, protocol.FailedMount)
	}
	for _, entry := range contract.ExpandedEnv() {
		if value, ok := container.EnvValue(entry.Name); !ok || value != entry.Value {
			failed = append(failed, protocol.FailedEnv)
			break
		}
	}
	if contract.AccessGroup != nil && !canAssign(*contract.AccessGroup) {
		failed = append(failed, protocol.FailedAccessGroup)
	}
	return failed
}

// CreateRequest is the create body and name for a recreated container.
type CreateRequest struct {
	Name    string
	Body    []byte
	Running bool
	Stop    int
}

// BuildCreateRequest reproduces container from its inspect output with the
// contract's mount and environment merged in. imageID is the image the
// container runs; it replaces the configured reference when that reference
// no longer resolves to the same image, so recreate never changes the image.
func BuildCreateRequest(container engine.Container, contract policy.Contract, consumerDirectory string, configuredImageID string) (CreateRequest, error) {
	var config map[string]any
	if err := json.Unmarshal(container.Raw.Config, &config); err != nil || config == nil {
		return CreateRequest{}, errors.New("inspect output has no configuration")
	}
	var hostConfig map[string]any
	if err := json.Unmarshal(container.Raw.HostConfig, &hostConfig); err != nil || hostConfig == nil {
		return CreateRequest{}, errors.New("inspect output has no host configuration")
	}
	if configuredImageID != container.Image && container.Image != "" {
		config["Image"] = container.Image
	}

	env := map[string]bool{}
	var environment []any
	contractEnv := contract.ExpandedEnv()
	for _, entry := range contractEnv {
		env[entry.Name] = true
	}
	if existing, ok := config["Env"].([]any); ok {
		for _, item := range existing {
			text, _ := item.(string)
			name, _, _ := strings.Cut(text, "=")
			if !env[name] {
				environment = append(environment, item)
			}
		}
	}
	for _, entry := range contractEnv {
		environment = append(environment, entry.Name+"="+entry.Value)
	}
	config["Env"] = environment

	covered := map[string]bool{}
	var binds []any
	if existing, ok := hostConfig["Binds"].([]any); ok {
		for _, item := range existing {
			text, _ := item.(string)
			if bindTarget(text) == contract.MountTarget {
				continue
			}
			covered[bindTarget(text)] = true
			binds = append(binds, item)
		}
	}
	var mounts []any
	if existing, ok := hostConfig["Mounts"].([]any); ok {
		for _, item := range existing {
			mount, _ := item.(map[string]any)
			target, _ := mount["Target"].(string)
			if filepath.Clean(target) == contract.MountTarget {
				continue
			}
			covered[filepath.Clean(target)] = true
			mounts = append(mounts, item)
		}
	}
	// Anonymous volumes are declared by the image or by Config.Volumes and
	// would be recreated empty; bind them back by their generated names.
	for _, mount := range container.Mounts {
		destination := filepath.Clean(mount.Destination)
		if mount.Type != "volume" || !anonymousVolumeName.MatchString(mount.Name) || covered[destination] || destination == contract.MountTarget {
			continue
		}
		mode := "rw"
		if !mount.RW {
			mode = "ro"
		}
		binds = append(binds, mount.Name+":"+destination+":"+mode)
		covered[destination] = true
	}
	mounts = append(mounts, map[string]any{
		"Type": "bind", "Source": consumerDirectory, "Target": contract.MountTarget, "ReadOnly": false,
	})
	hostConfig["Binds"] = binds
	hostConfig["Mounts"] = mounts
	if contract.AccessGroup != nil {
		group := strconv.FormatUint(uint64(*contract.AccessGroup), 10)
		present := false
		var groups []any
		if existing, ok := hostConfig["GroupAdd"].([]any); ok {
			groups = existing
			for _, item := range existing {
				if item == group {
					present = true
				}
			}
		}
		if !present {
			groups = append(groups, group)
		}
		hostConfig["GroupAdd"] = groups
	}

	body := map[string]any{}
	for key, value := range config {
		body[key] = value
	}
	body["HostConfig"] = hostConfig
	if networking, err := networkingConfig(container.Raw.NetworkSettings, container.ID); err != nil {
		return CreateRequest{}, err
	} else if networking != nil {
		body["NetworkingConfig"] = networking
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		return CreateRequest{}, err
	}
	stop := 10
	if container.Config.StopTimeout != nil {
		stop = *container.Config.StopTimeout
	}
	return CreateRequest{
		Name: container.ShortName(), Body: encoded, Stop: stop,
		Running: container.State.Status == "running" || container.State.Status == "restarting" || container.State.Status == "paused",
	}, nil
}

func bindTarget(bind string) string {
	parts := strings.Split(bind, ":")
	if len(parts) < 2 {
		return ""
	}
	return filepath.Clean(parts[1])
}

// networkingConfig rebuilds endpoint settings for every network the
// container joined, keeping user aliases, static addresses, links, MAC
// addresses, and driver options.
func networkingConfig(raw json.RawMessage, containerID string) (map[string]any, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var settings struct {
		Networks map[string]map[string]any `json:"Networks"`
	}
	if err := json.Unmarshal(raw, &settings); err != nil {
		return nil, errors.New("inspect output has invalid network settings")
	}
	if len(settings.Networks) == 0 {
		return nil, nil
	}
	endpoints := map[string]any{}
	shortID := containerID
	if len(shortID) > 12 {
		shortID = shortID[:12]
	}
	for name, endpoint := range settings.Networks {
		kept := map[string]any{}
		for _, field := range []string{"IPAMConfig", "Links", "MacAddress", "DriverOpts", "GwPriority"} {
			if value, ok := endpoint[field]; ok && value != nil {
				kept[field] = value
			}
		}
		if aliases, ok := endpoint["Aliases"].([]any); ok {
			var user []any
			for _, alias := range aliases {
				// The engine adds the short container identifier itself.
				if alias != shortID {
					user = append(user, alias)
				}
			}
			if len(user) > 0 {
				kept["Aliases"] = user
			}
		}
		endpoints[name] = kept
	}
	return map[string]any{"EndpointsConfig": endpoints}, nil
}
