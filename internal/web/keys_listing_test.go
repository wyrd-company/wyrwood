// ---
// relationships:
//   verifies: web-interface
// ---

package web

import (
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/wyrd-company/wyrwood/internal/config"
	"github.com/wyrd-company/wyrwood/internal/openbao/baotest"
	"github.com/wyrd-company/wyrwood/internal/web/oidctest"
)

const (
	didNotAnswer     = "OpenBao did not answer"
	retainedSuffix   = " Saved selections are retained."
	permissionDenied = "permission refused"
)

// keyListingPages returns the rendered keys page and new-policy editor.
func keyListingPages(t *testing.T, harness *harness) (string, string) {
	t.Helper()
	client := browser(t)
	harness.signIn(t, client, operator, oidctest.TamperNone)
	keys := get(t, client, harness.site.URL+"/keys")
	editor := get(t, client, harness.site.URL+"/policies/edit")
	if keys.status != 200 || editor.status != 200 {
		t.Fatalf("keys page = %d, policy editor = %d", keys.status, editor.status)
	}
	return keys.body, editor.body
}

func denyControllerPath(t *testing.T, harness *harness, path string) {
	t.Helper()
	// The exact path takes precedence over the controller policy's glob.
	if err := harness.bao.Root.Sys().PutPolicy(baotest.ControllerName, baotest.ControllerPolicy+`path "`+path+`" { capabilities = ["deny"] }`); err != nil {
		t.Fatal(err)
	}
}

func TestKeysPagesListAnImportedTransitKey(t *testing.T) {
	harness := startHarness(t, time.Hour)
	harness.bao.CreateTransitKey(t, "sample-generated", "ed25519")
	material := harness.bao.ImportTransitKey(t, "sample-imported")
	keys, editor := keyListingPages(t, harness)
	for _, name := range []string{"sample-generated", "sample-imported"} {
		if !strings.Contains(keys, ">"+name+"<") || !strings.Contains(editor, name) {
			t.Fatalf("%s missing from keys page or policy editor:\n%s\n%s", name, keys, editor)
		}
	}
	if strings.Count(keys, "SHA256:") != 2 {
		t.Fatalf("keys page fingerprints = %d, want 2:\n%s", strings.Count(keys, "SHA256:"), keys)
	}
	for page, body := range map[string]string{"keys page": keys, "policy editor": editor} {
		for _, unwanted := range []string{"import/", didNotAnswer, "could not be listed", "could not be read", material} {
			if strings.Contains(body, unwanted) {
				t.Fatalf("%s shows %q:\n%s", page, unwanted, body)
			}
		}
	}
}

func TestKeysPagesNameAnUnreadableTransitKey(t *testing.T) {
	harness := startHarness(t, time.Hour)
	harness.bao.CreateTransitKey(t, "sample-open", "ed25519")
	harness.bao.CreateTransitKey(t, "sample-locked", "ed25519")
	denyControllerPath(t, harness, "transit/keys/sample-locked")
	keys, editor := keyListingPages(t, harness)
	problem := "Transit key sample-locked could not be read: " + permissionDenied + "."
	if !strings.Contains(keys, ">sample-open<") || !strings.Contains(keys, problem) || strings.Contains(keys, ">sample-locked<") {
		t.Fatalf("keys page with an unreadable key:\n%s", keys)
	}
	if !strings.Contains(editor, "sample-open") || !strings.Contains(editor, problem+retainedSuffix) {
		t.Fatalf("policy editor with an unreadable key:\n%s", editor)
	}
	for page, body := range map[string]string{"keys page": keys, "policy editor": editor} {
		if strings.Contains(body, didNotAnswer) || strings.Contains(body, "could not be listed") {
			t.Fatalf("%s reports a failed list for one unreadable key:\n%s", page, body)
		}
	}
}

func TestKeysPagesReportARefusedTransitList(t *testing.T) {
	harness := startHarness(t, time.Hour)
	harness.bao.CreateTransitKey(t, "sample-key", "ed25519")
	harness.bao.CreateSSHRole(t, "sample-role", "sample-user", "30m")
	denyControllerPath(t, harness, "transit/keys")
	keys, editor := keyListingPages(t, harness)
	problem := "Transit keys could not be listed: " + permissionDenied + "."
	if !strings.Contains(keys, problem) || !strings.Contains(keys, ">sample-role<") {
		t.Fatalf("keys page with a refused list:\n%s", keys)
	}
	if !strings.Contains(editor, problem+retainedSuffix) {
		t.Fatalf("policy editor with a refused list:\n%s", editor)
	}
	for page, body := range map[string]string{"keys page": keys, "policy editor": editor} {
		if strings.Contains(body, didNotAnswer) {
			t.Fatalf("%s says OpenBao did not answer for a refused list:\n%s", page, body)
		}
	}
}

func TestKeysPageReportsARefusedRoleList(t *testing.T) {
	harness := startHarness(t, time.Hour)
	harness.bao.CreateTransitKey(t, "sample-key", "ed25519")
	denyControllerPath(t, harness, "ssh/roles")
	keys, _ := keyListingPages(t, harness)
	if !strings.Contains(keys, "SSH roles could not be listed: "+permissionDenied+".") || !strings.Contains(keys, ">sample-key<") || strings.Contains(keys, didNotAnswer) {
		t.Fatalf("keys page with a refused role list:\n%s", keys)
	}
}

// startHarnessDroppingOpenBao starts a harness whose controller reaches
// OpenBao through a proxy that drops the connection of each request whose path
// starts with prefix, so that only those requests get no answer.
func startHarnessDroppingOpenBao(t *testing.T, prefix string) *harness {
	t.Helper()
	return startConfiguredHarness(t, time.Hour, func(configuration *config.Controller) {
		target, err := url.Parse(configuration.OpenBao.Address)
		if err != nil {
			t.Fatal(err)
		}
		forward := httputil.NewSingleHostReverseProxy(target)
		proxy := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if strings.HasPrefix(request.URL.Path, prefix) {
				if connection, _, err := writer.(http.Hijacker).Hijack(); err == nil {
					_ = connection.Close()
				}
				return
			}
			forward.ServeHTTP(writer, request)
		}))
		t.Cleanup(proxy.Close)
		configuration.OpenBao.Address = proxy.URL
	})
}

func TestKeysPageReportsAnUnansweredRoleList(t *testing.T) {
	harness := startHarnessDroppingOpenBao(t, "/v1/ssh/roles")
	harness.bao.CreateTransitKey(t, "sample-key", "ed25519")
	keys, _ := keyListingPages(t, harness)
	if !strings.Contains(keys, didNotAnswer+". The lists below may be incomplete") || !strings.Contains(keys, ">sample-key<") || strings.Contains(keys, "could not be listed") {
		t.Fatalf("keys page with an unanswered role list:\n%s", keys)
	}
}

// TestKeysPagesKeepKeysReadBeforeAnUnansweredRead reads one key and then gets
// no answer for the next, as an OpenBao that goes away during the reads.
func TestKeysPagesKeepKeysReadBeforeAnUnansweredRead(t *testing.T) {
	harness := startHarnessDroppingOpenBao(t, "/v1/transit/keys/sample-later")
	harness.bao.CreateTransitKey(t, "sample-earlier", "ed25519")
	harness.bao.CreateTransitKey(t, "sample-later", "ed25519")
	keys, editor := keyListingPages(t, harness)
	problem := "Transit key sample-later could not be read: " + didNotAnswer + "."
	if !strings.Contains(keys, ">sample-earlier<") || strings.Contains(keys, ">sample-later<") ||
		!strings.Contains(keys, didNotAnswer+". The lists below may be incomplete") || !strings.Contains(keys, problem) {
		t.Fatalf("keys page after an unanswered read:\n%s", keys)
	}
	if !strings.Contains(editor, "sample-earlier") || !strings.Contains(editor, problem+retainedSuffix) ||
		!strings.Contains(editor, didNotAnswer+", so the Transit key list may be incomplete."+retainedSuffix) {
		t.Fatalf("policy editor after an unanswered read:\n%s", editor)
	}
}

func TestKeysPagesReportAnOpenBaoThatDoesNotAnswer(t *testing.T) {
	harness := startHarness(t, time.Hour)
	harness.bao.CreateTransitKey(t, "sample-key", "ed25519")
	harness.bao.Stop()
	keys, editor := keyListingPages(t, harness)
	if !strings.Contains(keys, didNotAnswer+". The lists below may be incomplete") {
		t.Fatalf("keys page without OpenBao:\n%s", keys)
	}
	if !strings.Contains(editor, didNotAnswer+", so the Transit key list may be incomplete."+retainedSuffix) {
		t.Fatalf("policy editor without OpenBao:\n%s", editor)
	}
	for page, body := range map[string]string{"keys page": keys, "policy editor": editor} {
		if strings.Contains(body, permissionDenied) || strings.Contains(body, "could not be read") {
			t.Fatalf("%s names another category without OpenBao:\n%s", page, body)
		}
	}
}
