// ---
// relationships:
//   implements: web-interface
//   references: container-contract
// ---

package web

import (
	"encoding/csv"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/wyrd-company/wyrwood/internal/policy"
	"github.com/wyrd-company/wyrwood/internal/protocol"
)

type containerSetup struct {
	Source, Target, Compose, DockerRun string
}

// bindingSetup uses the agent's directory, never an inferred mount or a
// controller-side default. Existing inventories can omit this observation.
func bindingSetup(container protocol.Container, contract policy.Contract) *containerSetup {
	if container.ConsumerDirectory == "" || container.Image == "" {
		return nil
	}
	source, target := container.ConsumerDirectory, contract.MountTarget
	composeValue := func(value string) string { return strings.ReplaceAll(value, "$", "$$") }
	environment := map[string]string{}
	command := []string{"docker run", "--name " + shellQuote(container.Name)}
	var mount strings.Builder
	writer := csv.NewWriter(&mount)
	_ = writer.Write([]string{"type=bind", "source=" + source, "target=" + target})
	writer.Flush()
	command = append(command, "--mount "+shellQuote(strings.TrimSuffix(mount.String(), "\n")))
	for _, entry := range contract.ExpandedEnv() {
		environment[entry.Name] = composeValue(entry.Value)
		command = append(command, "--env "+shellQuote(entry.Name+"="+entry.Value))
	}
	if contract.AccessGroup != nil {
		command = append(command, "--group-add "+shellQuote(strconv.FormatUint(uint64(*contract.AccessGroup), 10)))
	}
	command = append(command, shellQuote(container.Image))
	// Long syntax prevents ':' in a host path from changing the mount shape.
	service := map[string]any{
		"image": composeValue(container.Image), "container_name": composeValue(container.Name),
		"volumes": []any{map[string]any{
			"type": "bind", "source": composeValue(source), "target": composeValue(target),
			"bind": map[string]any{"create_host_path": false},
		}},
	}
	if contract.AccessGroup != nil {
		service["group_add"] = []string{strconv.FormatUint(uint64(*contract.AccessGroup), 10)}
	}
	if len(environment) > 0 {
		service["environment"] = environment
	}
	// The document contains only maps, strings and a bool, all supported by yaml.
	fragment, _ := yaml.Marshal(map[string]any{"services": map[string]any{"app": service}})
	return &containerSetup{Source: source, Target: target, Compose: string(fragment), DockerRun: strings.Join(command, " \\\n  ")}
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}
