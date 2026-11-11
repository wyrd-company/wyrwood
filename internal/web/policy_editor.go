// ---
// relationships:
//   implements: web-interface
//   uses: controller
// ---

package web

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/wyrd-company/wyrwood/internal/openbao"
)

func (server *Server) fillPolicyChoices(ctx context.Context, page *policyPage) {
	page.KVMounts = server.controller.OpenBao().Mounts().KV
	listing, err := server.controller.OpenBao().ListTransitKeys(ctx)
	switch {
	case openbao.Unreachable(err):
		page.IdentityProblems = append(page.IdentityProblems, "OpenBao did not answer, so the Transit key list may be incomplete. Saved selections are retained.")
	case err != nil:
		page.IdentityProblems = append(page.IdentityProblems, "Transit keys could not be listed: "+openBaoProblem(err)+". Saved selections are retained.")
	}
	page.IdentityProblems = append(page.IdentityProblems, unreadableTransitKeyProblems(listing, " Saved selections are retained.")...)
	for _, key := range listing.Keys {
		page.AvailableTransitKeys = append(page.AvailableTransitKeys, key.Name)
	}
	roles, err := server.controller.OpenBao().ListSSHRoles(ctx)
	if err != nil {
		page.IdentityProblems = append(page.IdentityProblems, "SSH roles could not be listed. Saved selections are retained.")
	}
	for _, role := range roles {
		page.AvailableCARoles = append(page.AvailableCARoles, role.Name)
	}
}

func (server *Server) handleKVPaths(writer http.ResponseWriter, request *http.Request) {
	paths, err := server.controller.OpenBao().ListKVPaths(request.Context(), request.URL.Query().Get("mount"), request.URL.Query().Get("prefix"))
	if err != nil {
		// Do not expose upstream response text or silently treat a denied list
		// as an empty directory. Manual paths and raw HCL remain available.
		http.Error(writer, "KV paths could not be listed. Check the mount configuration and metadata LIST permission.", http.StatusUnprocessableEntity)
		return
	}
	if paths == nil {
		paths = []string{}
	}
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(struct{ Paths []string }{paths})
}
