// ---
// relationships:
//   verifies: engine-proxy
// ---

package engineproxy

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestExactAllowListAndHostPermission(t *testing.T) {
	filters := url.QueryEscape(`{"type":["container"],"event":["create","start","die","destroy","rename"]}`)
	reads := []struct{ method, path string }{
		{"GET", "/containers/json?all=1"}, {"GET", "/containers/sample/json"},
		{"GET", "/events?filters=" + filters}, {"GET", "/images/registry.example%3A5000%2Fsample%2Fimage%3Atag/json"},
	}
	writes := []struct{ method, path string }{
		{"POST", "/containers/sample/stop?t=-1"}, {"DELETE", "/containers/sample?v=0&force=0"},
		{"POST", "/containers/create?name=sample"}, {"POST", "/containers/sample/start"},
	}
	for _, allowed := range []bool{false, true} {
		for _, route := range append(reads, writes...) {
			for _, prefix := range []string{"", "/v1.45"} {
				t.Run(route.method+prefix+route.path+map[bool]string{false: "/disabled", true: "/enabled"}[allowed], func(t *testing.T) {
					var body *strings.Reader = strings.NewReader("")
					if strings.Contains(route.path, "/create?") {
						body = strings.NewReader(`{"Image":"sample"}`)
					}
					req := httptest.NewRequest(route.method, prefix+route.path, body)
					if body.Len() > 0 {
						req.Header.Set("Content-Type", "application/json")
					}
					_, status := authorize(req, allowed)
					want := 0
					if route.method != "GET" && !allowed {
						want = http.StatusForbidden
					}
					if status != want {
						t.Fatalf("authorize = %d, want %d", status, want)
					}
				})
			}
		}
	}
}

func TestRejectsEveryOtherSurface(t *testing.T) {
	for _, path := range []string{
		"/containers/json", "/containers/json?all=0", "/containers/sample/json?broken;pair", "/containers/json?all=1&all=1", "/containers/json?all=1&size=1",
		"/containers/sample/json?x=1", "/containers/sample/logs", "/containers/sample/archive?path=/",
		"/images/sample/get", "/images/create", "/info", "/version", "/_ping", "/events",
		"/events?filters=%7B%22type%22:%5B%22container%22%5D%7D", "/containers/sample/start/",
		"/containers/sample/restart", "/containers/sample/kill", "/containers/sample/exec",
		"/containers/sample/attach", "/containers/sample/rename", "/containers/sample/update",
		"/containers/sample/pause", "/containers/sample/unpause", "/build", "/volumes/create",
		"/networks/create", "/plugins", "/swarm", "/Containers/json?all=1",
		"/containers//sample/json", "/containers/../sample/json", "/containers/%2e%2e/json",
		"/containers/sample%2fother/json", "/containers/sample%252fother/json", "/containers/sample%5cother/json",
		"/containers/create?name=sample&platform=x", "/containers/create?name=sample&name=other",
		"/containers/create?name=", "/containers/sample?force=1&v=0", "/containers/sample?force=0&v=1",
		"/containers/sample?force=0&v=0&link=1", "/containers/sample/stop?t=-2", "/containers/sample/stop?t=abc",
		"/containers/sample/stop?t=1&t=2", "/v1.45/v1.45/containers/json?all=1", "/v1./containers/json?all=1",
		"/images/sample/extra/json", "/images/sample%252Fother/json", "/images/%2e%2e/json",
	} {
		for _, method := range []string{"GET", "HEAD", "POST", "DELETE", "PUT", "PATCH", "OPTIONS", "CONNECT"} {
			req := httptest.NewRequest(method, path, nil)
			_, status := authorize(req, true)
			if status == 0 {
				t.Errorf("allowed %s %s", method, path)
			}
		}
	}
	for _, header := range []string{"Upgrade", "X-HTTP-Method-Override", "X-Method-Override", "X-HTTP-Method"} {
		req := httptest.NewRequest("GET", "/containers/json?all=1", nil)
		req.Header.Set(header, "anything")
		if _, status := authorize(req, true); status == 0 {
			t.Errorf("accepted %s", header)
		}
	}
	req := httptest.NewRequest("GET", "http://other/containers/json?all=1", nil)
	if _, status := authorize(req, true); status == 0 {
		t.Error("accepted absolute target")
	}
	req = httptest.NewRequest("GET", "/containers/json?all=1", strings.NewReader("payload"))
	if _, status := authorize(req, true); status == 0 {
		t.Error("accepted read body")
	}
}

func TestEventFiltersHaveOneExactMeaning(t *testing.T) {
	for _, value := range []string{
		`{"type":["container"],"type":["container"],"event":["create","start","die","destroy","rename"]}`,
		`{"type":["container"],"scope":[]}`,
		`{"type":["container"],"event":["create","start","die","destroy","rename"],"type":["image"]}`,
		`{"type":["container"],"event":["create","start","die","destroy","rename","rename"]}`,
		`{"type":["container"],"event":["create","start","die","destroy","rename"],"scope":["swarm"]}`,
	} {
		req := httptest.NewRequest("GET", "/events?filters="+url.QueryEscape(value), nil)
		if _, status := authorize(req, true); status == 0 {
			t.Errorf("accepted filters %s", value)
		}
	}
}

func TestCreateMediaTypeAndOtherBodiesAreRejected(t *testing.T) {
	empty := httptest.NewRequest("POST", "/containers/create?name=sample", nil)
	empty.Header.Set("Content-Type", "application/json")
	if _, status := authorize(empty, true); status == 0 {
		t.Fatal("accepted empty create")
	}

	for _, contentType := range []string{"", "text/plain", "broken;"} {
		req := httptest.NewRequest("POST", "/containers/create?name=sample", strings.NewReader(`{}`))
		req.Header.Set("Content-Type", contentType)
		if _, status := authorize(req, true); status == 0 {
			t.Errorf("accepted media type %q", contentType)
		}
	}
	for _, methodPath := range []struct{ method, path string }{{"POST", "/containers/sample/start"}, {"POST", "/containers/sample/stop?t=1"}, {"DELETE", "/containers/sample?force=0&v=0"}} {
		req := httptest.NewRequest(methodPath.method, methodPath.path, strings.NewReader("payload"))
		if _, status := authorize(req, true); status == 0 {
			t.Error("accepted mutation body", methodPath)
		}
	}
}

func TestMethodsCannotSubstituteForAnAllowedRoute(t *testing.T) {
	filters := url.QueryEscape(`{"type":["container"],"event":["create","start","die","destroy","rename"]}`)
	routes := []struct{ method, path string }{
		{"GET", "/containers/json?all=1"}, {"GET", "/containers/sample/json"}, {"GET", "/events?filters=" + filters}, {"GET", "/images/sample/json"},
		{"POST", "/containers/create?name=sample"}, {"POST", "/containers/sample/stop?t=1"}, {"POST", "/containers/sample/start"}, {"DELETE", "/containers/sample?v=0&force=0"},
	}
	for _, route := range routes {
		for _, method := range []string{"GET", "HEAD", "POST", "DELETE", "PUT", "PATCH", "OPTIONS", "CONNECT"} {
			if method == route.method {
				continue
			}
			body := ""
			if strings.HasPrefix(route.path, "/containers/create?") {
				body = `{"Image":"sample"}`
			}
			req := httptest.NewRequest(method, route.path, strings.NewReader(body))
			if body != "" {
				req.Header.Set("Content-Type", "application/json")
			}
			if _, status := authorize(req, true); status == 0 {
				t.Errorf("method substitution allowed: %s %s", method, route.path)
			}
		}
	}
}
