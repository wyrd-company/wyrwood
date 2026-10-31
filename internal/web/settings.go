// ---
// relationships:
//   implements: web-interface
//   uses: configuration
// ---

package web

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/wyrd-company/wyrwood/internal/config"
)

type setting struct{ Label, Value string }
type settingsSection struct {
	Title    string
	Settings []setting
}
type settingsPage struct {
	layout
	Sections []settingsSection
}

// projectSettings is an allowlist, never a serialization of configuration.
// Credential values, credential-file paths, and URL userinfo, paths, queries,
// and fragments must not cross this boundary. New config fields are private
// until explicitly selected here.
func projectSettings(c config.Controller, version string) []settingsSection {
	enabled := "Disabled"
	if c.UpdateChecks.Enabled {
		enabled = "Enabled"
	}
	localAgent := "Disabled"
	if c.LocalAgent {
		localAgent = "Enabled"
	}
	mounts := make([]string, 0, len(c.OpenBao.SecretMounts))
	for _, mount := range c.OpenBao.SecretMounts {
		mounts = append(mounts, mount.Path+" ("+mount.Type+")")
	}
	return []settingsSection{
		{"Controller", []setting{
			{"Version", version}, {"HTTP listen address", c.HTTPListen}, {"SSH listen address", c.SSHListen},
			{"Local agent", localAgent},
			{"Session lifetime", c.SessionTTL.String()}, {"State directory", c.StateDirectory},
		}},
		{"OpenBao", []setting{
			{"Endpoint origin", settingsOrigin(c.OpenBao.Address)}, {"Namespace", c.OpenBao.Namespace},
			{"Custom CA configured", strconv.FormatBool(c.OpenBao.CAFile != "")},
			{"AppRole mount", c.OpenBao.AppRoleMount}, {"Transit mount", c.OpenBao.TransitMount},
			{"SSH mount", c.OpenBao.SSHMount}, {"Secret engine catalog", strings.Join(mounts, ", ")},
			{"Web UI origin", settingsOrigin(c.OpenBao.UIURL)},
		}},
		{"Operator sign-in", []setting{
			{"Provider", c.OIDC.ProviderName}, {"Issuer origin", settingsOrigin(c.OIDC.Issuer)},
			{"Client ID", c.OIDC.ClientID}, {"Redirect origin", settingsOrigin(c.OIDC.RedirectURL)},
			{"Groups claim", c.OIDC.GroupsClaim}, {"Allowed groups", strings.Join(c.OIDC.AllowedGroups, ", ")},
		}},
		{"Update checks", []setting{
			{"Release checks", enabled}, {"Check interval", c.UpdateChecks.Interval.String()},
			{"Request timeout", c.UpdateChecks.Timeout.String()},
		}},
	}
}

func settingsOrigin(value string) string {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "https" && parsed.Scheme != "http") {
		return ""
	}
	return (&url.URL{Scheme: parsed.Scheme, Host: parsed.Host}).String()
}

func (server *Server) handleSettings(writer http.ResponseWriter, request *http.Request) {
	server.render(writer, request, "settings", settingsPage{
		layout:   server.layout(request, "Settings", "settings"),
		Sections: projectSettings(server.controller.Configuration(), server.version),
	})
}
