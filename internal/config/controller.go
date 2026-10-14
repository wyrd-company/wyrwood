// ---
// relationships:
//   implements: configuration
//   uses: controller
// ---

package config

import (
	"strings"
	"time"
)

// Controller defaults.
const (
	DefaultHTTPListen      = "127.0.0.1:8080"
	DefaultSSHListen       = "0.0.0.0:2222"
	DefaultStateDirectory  = "/var/lib/wyrwood"
	DefaultAppRoleMount    = "approle"
	DefaultTransitMount    = "transit"
	DefaultSSHMount        = "ssh"
	DefaultGroupsClaim     = "groups"
	DefaultProviderName    = "your identity provider"
	defaultSessionTTL      = 12 * time.Hour
	minimumSessionTTL      = 15 * time.Minute
	maximumSessionTTL      = 24 * time.Hour
	maximumProviderNameLen = 64
	callbackPath           = "/auth/callback"
)

// Controller is the validated controller configuration.
type Controller struct {
	HTTPListen     string
	SessionTTL     time.Duration
	SSHListen      string
	StateDirectory string
	OpenBao        ControllerOpenBao
	OIDC           OIDC
}

// ControllerOpenBao is the controller's OpenBao connection.
type ControllerOpenBao struct {
	Address      string
	CAFile       string
	Namespace    string
	AppRoleMount string
	RoleID       string
	SecretIDFile string
	TransitMount string
	SSHMount     string
}

// OIDC is the operator sign-in configuration.
type OIDC struct {
	ProviderName     string
	Issuer           string
	ClientID         string
	ClientSecretFile string
	RedirectURL      string
	GroupsClaim      string
	AllowedGroups    []string
}

type controllerDocument struct {
	HTTP *struct {
		Listen     *string `yaml:"listen"`
		SessionTTL *string `yaml:"session-ttl"`
	} `yaml:"http"`
	SSH *struct {
		Listen *string `yaml:"listen"`
	} `yaml:"ssh"`
	State *struct {
		Directory *string `yaml:"directory"`
	} `yaml:"state"`
	OpenBao *struct {
		Address   string  `yaml:"address"`
		CAFile    *string `yaml:"ca-file"`
		Namespace *string `yaml:"namespace"`
		AppRole   *struct {
			Mount        *string `yaml:"mount"`
			RoleID       string  `yaml:"role-id"`
			SecretIDFile string  `yaml:"secret-id-file"`
		} `yaml:"approle"`
		TransitMount *string `yaml:"transit-mount"`
		SSHMount     *string `yaml:"ssh-mount"`
	} `yaml:"openbao"`
	OIDC *struct {
		ProviderName     *string  `yaml:"provider-name"`
		Issuer           string   `yaml:"issuer"`
		ClientID         string   `yaml:"client-id"`
		ClientSecretFile string   `yaml:"client-secret-file"`
		RedirectURL      string   `yaml:"redirect-url"`
		GroupsClaim      *string  `yaml:"groups-claim"`
		AllowedGroups    []string `yaml:"allowed-groups"`
	} `yaml:"oidc"`
}

// LoadController reads and validates the controller configuration at path.
func LoadController(path string) (Controller, error) {
	data, err := readBounded(path, MaximumDocumentBytes)
	if err != nil {
		return Controller{}, err
	}
	return ParseController(data)
}

// ParseController validates one controller configuration document.
func ParseController(data []byte) (Controller, error) {
	var document controllerDocument
	if err := decodeStrict(data, &document); err != nil {
		return Controller{}, err
	}
	result := Controller{
		HTTPListen:     DefaultHTTPListen,
		SessionTTL:     defaultSessionTTL,
		SSHListen:      DefaultSSHListen,
		StateDirectory: DefaultStateDirectory,
	}
	var err error
	if document.HTTP != nil {
		if document.HTTP.Listen != nil {
			result.HTTPListen = *document.HTTP.Listen
		}
		if document.HTTP.SessionTTL != nil {
			if result.SessionTTL, err = parseBoundedDuration("http.session-ttl", *document.HTTP.SessionTTL, minimumSessionTTL, maximumSessionTTL); err != nil {
				return Controller{}, err
			}
		}
	}
	if err := validListen("http.listen", result.HTTPListen); err != nil {
		return Controller{}, err
	}
	if document.SSH != nil && document.SSH.Listen != nil {
		result.SSHListen = *document.SSH.Listen
	}
	if err := validListen("ssh.listen", result.SSHListen); err != nil {
		return Controller{}, err
	}
	if document.State != nil && document.State.Directory != nil {
		if result.StateDirectory, err = canonicalPath("state.directory", *document.State.Directory); err != nil {
			return Controller{}, err
		}
	}
	if result.OpenBao, err = parseControllerOpenBao(document); err != nil {
		return Controller{}, err
	}
	if result.OIDC, err = parseOIDC(document); err != nil {
		return Controller{}, err
	}
	return result, nil
}

func parseControllerOpenBao(document controllerDocument) (ControllerOpenBao, error) {
	source := document.OpenBao
	if source == nil {
		return ControllerOpenBao{}, invalid("openbao is required")
	}
	if _, err := absoluteURL("openbao.address", source.Address, "https", "http"); err != nil {
		return ControllerOpenBao{}, err
	}
	result := ControllerOpenBao{
		Address:      strings.TrimRight(source.Address, "/"),
		AppRoleMount: DefaultAppRoleMount,
		TransitMount: DefaultTransitMount,
		SSHMount:     DefaultSSHMount,
	}
	var err error
	if source.CAFile != nil {
		if result.CAFile, err = canonicalPath("openbao.ca-file", *source.CAFile); err != nil {
			return ControllerOpenBao{}, err
		}
	}
	if source.Namespace != nil {
		result.Namespace = strings.Trim(*source.Namespace, "/")
	}
	if source.AppRole == nil {
		return ControllerOpenBao{}, invalid("openbao.approle is required")
	}
	if source.AppRole.Mount != nil {
		result.AppRoleMount = *source.AppRole.Mount
	}
	if source.AppRole.RoleID == "" {
		return ControllerOpenBao{}, invalid("openbao.approle.role-id is required")
	}
	result.RoleID = source.AppRole.RoleID
	if result.SecretIDFile, err = canonicalPath("openbao.approle.secret-id-file", source.AppRole.SecretIDFile); err != nil {
		return ControllerOpenBao{}, err
	}
	if source.TransitMount != nil {
		result.TransitMount = *source.TransitMount
	}
	if source.SSHMount != nil {
		result.SSHMount = *source.SSHMount
	}
	for field, mount := range map[string]string{
		"openbao.approle.mount": result.AppRoleMount,
		"openbao.transit-mount": result.TransitMount,
		"openbao.ssh-mount":     result.SSHMount,
	} {
		if !validMount(mount) {
			return ControllerOpenBao{}, invalid("%s must be a mount path without surrounding slashes", field)
		}
	}
	return result, nil
}

func parseOIDC(document controllerDocument) (OIDC, error) {
	source := document.OIDC
	if source == nil {
		return OIDC{}, invalid("oidc is required")
	}
	result := OIDC{
		ProviderName: DefaultProviderName,
		GroupsClaim:  DefaultGroupsClaim,
		ClientID:     source.ClientID,
	}
	if source.ProviderName != nil {
		if *source.ProviderName == "" || len(*source.ProviderName) > maximumProviderNameLen {
			return OIDC{}, invalid("oidc.provider-name must be 1 to 64 characters")
		}
		result.ProviderName = *source.ProviderName
	}
	issuer, err := absoluteURL("oidc.issuer", source.Issuer, "https", "http")
	if err != nil {
		return OIDC{}, err
	}
	result.Issuer = issuer.String()
	if result.ClientID == "" {
		return OIDC{}, invalid("oidc.client-id is required")
	}
	if result.ClientSecretFile, err = canonicalPath("oidc.client-secret-file", source.ClientSecretFile); err != nil {
		return OIDC{}, err
	}
	redirect, err := absoluteURL("oidc.redirect-url", source.RedirectURL, "https", "http")
	if err != nil {
		return OIDC{}, err
	}
	if redirect.Path != callbackPath || redirect.RawQuery != "" || redirect.Fragment != "" {
		return OIDC{}, invalid("oidc.redirect-url must end in %s", callbackPath)
	}
	result.RedirectURL = redirect.String()
	if source.GroupsClaim != nil {
		if *source.GroupsClaim == "" {
			return OIDC{}, invalid("oidc.groups-claim must not be empty")
		}
		result.GroupsClaim = *source.GroupsClaim
	}
	if len(source.AllowedGroups) == 0 {
		return OIDC{}, invalid("oidc.allowed-groups must name at least one group")
	}
	seen := map[string]bool{}
	for _, group := range source.AllowedGroups {
		if group == "" || seen[group] {
			return OIDC{}, invalid("oidc.allowed-groups must be unique non-empty names")
		}
		seen[group] = true
	}
	result.AllowedGroups = append([]string(nil), source.AllowedGroups...)
	return result, nil
}

func validMount(value string) bool {
	if value == "" || strings.HasPrefix(value, "/") || strings.HasSuffix(value, "/") {
		return false
	}
	for _, character := range value {
		if !(character == '-' || character == '_' || character == '/' || character == '.' ||
			(character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9')) {
			return false
		}
	}
	return !strings.Contains(value, "..")
}
