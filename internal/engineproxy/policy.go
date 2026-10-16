// ---
// relationships:
//   implements: engine-proxy
// ---

// Package engineproxy enforces the host's Docker permission outside the agent.
package engineproxy

import (
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

var apiPrefix = regexp.MustCompile(`^/v[0-9]+\.[0-9]+/`)
var containerName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]*$`)
var imageReference = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:/@-]*$`)

// authorize validates and canonicalizes exactly the request that is forwarded.
// A zero status grants access; every other result is a local HTTP rejection.
func authorize(r *http.Request, recreate bool) (string, int) {
	if r.URL.IsAbs() || r.URL.Opaque != "" || r.URL.User != nil || r.URL.Fragment != "" || !strings.HasPrefix(r.RequestURI, "/") {
		return "request", http.StatusBadRequest
	}
	for _, h := range []string{"Upgrade", "X-HTTP-Method-Override", "X-Method-Override", "X-HTTP-Method"} {
		if _, exists := r.Header[http.CanonicalHeaderKey(h)]; exists {
			return "request", http.StatusForbidden
		}
	}
	path := r.URL.EscapedPath()
	prefix := ""
	if match := apiPrefix.FindString(path); match != "" {
		prefix = strings.TrimSuffix(match, "/")
		path = path[len(prefix):]
	}
	parts := strings.Split(path, "/")
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return "request", http.StatusBadRequest
	}
	operation := ""
	write := false
	switch {
	case r.Method == http.MethodGet && path == "/containers/json" && exactQuery(query, map[string]string{"all": "1"}):
		operation = "list"
	case r.Method == http.MethodGet && len(parts) == 4 && parts[1] == "containers" && containerName.MatchString(parts[2]) && parts[3] == "json" && len(query) == 0:
		operation = "inspect"
	case r.Method == http.MethodGet && path == "/events" && len(query) == 1 && len(query["filters"]) == 1 && validFilters(query.Get("filters")):
		operation = "events"
	case r.Method == http.MethodGet && len(parts) == 4 && parts[1] == "images" && parts[3] == "json" && len(query) == 0:
		reference, decodeErr := url.PathUnescape(parts[2])
		if decodeErr == nil && imageReference.MatchString(reference) && !strings.Contains(reference, "//") && !slices.Contains(strings.Split(reference, "/"), "..") && !slices.Contains(strings.Split(reference, "/"), ".") {
			operation = "image-inspect"
			path = "/images/" + url.PathEscape(reference) + "/json"
		}
	case r.Method == http.MethodPost && path == "/containers/create" && len(query) == 1 && len(query["name"]) == 1 && containerName.MatchString(query.Get("name")):
		operation = "create"
		write = true
	case r.Method == http.MethodDelete && len(parts) == 3 && parts[1] == "containers" && containerName.MatchString(parts[2]) && exactQuery(query, map[string]string{"v": "0", "force": "0"}):
		operation = "remove"
		write = true
	case r.Method == http.MethodPost && len(parts) == 4 && parts[1] == "containers" && containerName.MatchString(parts[2]):
		if parts[3] == "start" && len(query) == 0 {
			operation = "start"
			write = true
		}
		if parts[3] == "stop" && len(query) == 1 && len(query["t"]) == 1 {
			if t, err := strconv.ParseInt(query.Get("t"), 10, 64); err == nil && t >= -1 {
				operation = "stop"
				write = true
			}
		}
	}
	if operation == "" {
		return "request", http.StatusForbidden
	}
	// Check host permission before any create-body access, including media type.
	if write && !recreate {
		return operation, http.StatusForbidden
	}
	if operation == "create" {
		media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || media != "application/json" || r.Body == nil || r.Body == http.NoBody {
			return operation, http.StatusBadRequest
		}
	} else if r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
		return operation, http.StatusBadRequest
	}
	decoded, err := url.PathUnescape(prefix + path)
	if err != nil {
		return operation, http.StatusBadRequest
	}
	r.URL.Path = decoded
	r.URL.RawPath = prefix + path
	r.URL.RawQuery = query.Encode()
	return operation, 0
}

func exactQuery(values url.Values, want map[string]string) bool {
	if len(values) != len(want) {
		return false
	}
	for key, value := range want {
		if len(values[key]) != 1 || values.Get(key) != value {
			return false
		}
	}
	return true
}

func validFilters(value string) bool {
	// Token decoding, rather than map unmarshalling, detects duplicate keys.
	decoder := json.NewDecoder(strings.NewReader(value))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return false
	}
	seen := map[string]bool{}
	for decoder.More() {
		key, err := decoder.Token()
		name, ok := key.(string)
		if err != nil || !ok || seen[name] {
			return false
		}
		seen[name] = true
		var values []string
		if decoder.Decode(&values) != nil {
			return false
		}
		slices.Sort(values)
		switch name {
		case "type":
			if !slices.Equal(values, []string{"container"}) {
				return false
			}
		case "event":
			if !slices.Equal(values, []string{"create", "destroy", "die", "rename", "start"}) {
				return false
			}
		default:
			return false
		}
	}
	token, err = decoder.Token()
	if err != nil || token != json.Delim('}') || len(seen) != 2 {
		return false
	}
	var trailing any
	return decoder.Decode(&trailing) == io.EOF
}
