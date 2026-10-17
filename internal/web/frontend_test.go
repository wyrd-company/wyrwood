// ---
// relationships:
//   verifies: web-interface
// ---

package web

import (
	"bytes"
	"encoding/json"
	"html"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

var pageDataPattern = regexp.MustCompile(`<script id="wyrwood-page" type="application/json">(.*?)</script>`)

// The Go HTTP client does not execute JavaScript. Render the same React App
// with the test-only Node bundle so workflow assertions still inspect the UI,
// including conditional controls and native form fields, rather than JSON text.
func renderedPage(t *testing.T, body []byte) string {
	t.Helper()
	match := pageDataPattern.FindSubmatch(body)
	if match == nil {
		return html.UnescapeString(string(body))
	}
	return renderReact(t, match[1])
}

func renderReact(t *testing.T, payload []byte) string {
	t.Helper()
	command := exec.Command("node", "testdist/render.mjs")
	command.Stdin = bytes.NewReader(payload)
	var diagnostics bytes.Buffer
	command.Stderr = &diagnostics
	output, err := command.Output()
	if err != nil {
		t.Fatalf("render React (run task test to build test renderer): %v\n%s", err, diagnostics.String())
	}
	return html.UnescapeString(string(output))
}

func renderModel(t *testing.T, name string, data any) string {
	t.Helper()
	payload, err := json.Marshal(map[string]any{"page": name, "data": data})
	if err != nil {
		t.Fatal(err)
	}
	return renderReact(t, payload)
}

func TestEmbeddedFrontendAndPageData(t *testing.T) {
	shell, err := assets.ReadFile("dist/index.html")
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{shell: shell}
	recorder := httptest.NewRecorder()
	value := `</script><script>alert("sample")</script>&` + "\u2028\u2029"
	server.render(recorder, httptest.NewRequest("GET", "/policies/edit", nil), "policy", policyPage{HCL: value})
	body := recorder.Body.String()
	if strings.Contains(body, value) || !strings.Contains(body, `\u003c/script\u003e`) {
		t.Fatalf("unsafe page data: %s", body)
	}
	match := pageDataPattern.FindStringSubmatch(body)
	if match == nil {
		t.Fatal("missing bootstrap data")
	}
	var payload struct {
		Page string
		Data policyPage
	}
	if err := json.Unmarshal([]byte(match[1]), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Page != "policy" || payload.Data.HCL != value {
		t.Fatalf("page data did not round trip: %#v", payload)
	}
	scripts := regexp.MustCompile(`src="(/static/assets/[^"]+\.js)"`).FindAllStringSubmatch(body, -1)
	styles := regexp.MustCompile(`href="(/static/assets/[^"]+\.css)"`).FindAllStringSubmatch(body, -1)
	if len(scripts) == 0 || len(styles) == 0 {
		t.Fatalf("missing built JavaScript or CSS: %s", body)
	}
	for _, paths := range [][][]string{scripts, styles} {
		for _, path := range paths {
			if _, err := assets.ReadFile("dist/" + strings.TrimPrefix(path[1], "/static/")); err != nil {
				t.Fatal(err)
			}
		}
	}
	if strings.Contains(body, "<!--wyrwood-page-->") {
		t.Fatal("bootstrap placeholder remains")
	}
}

func TestFrontendSecurityHeaders(t *testing.T) {
	recorder := httptest.NewRecorder()
	securityHeaders(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) { writer.WriteHeader(http.StatusNoContent) })).ServeHTTP(recorder, httptest.NewRequest("GET", "/sign-in", nil))
	csp := recorder.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src 'self';") || !strings.Contains(csp, "default-src 'none';") || !strings.Contains(csp, "connect-src 'self';") {
		t.Fatalf("bundled scripts must be same-origin with no inline script allowance: %s", csp)
	}
	for name, value := range map[string]string{"Cache-Control": "no-store", "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "same-origin"} {
		if got := recorder.Header().Get(name); got != value {
			t.Fatalf("%s = %q, want %q", name, got, value)
		}
	}
}
