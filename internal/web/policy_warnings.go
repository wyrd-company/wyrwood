// ---
// relationships:
//   implements: web-interface
//   uses: policy
// ---

package web

import (
	"encoding/json"
	"net/http"
)

// handlePolicyWarnings shares the editor's initial checks with unsaved HCL.
// It has no persistence or OpenBao side effects and never gates policy saving.
func (server *Server) handlePolicyWarnings(writer http.ResponseWriter, request *http.Request) {
	warnings := server.controller.PolicyWarnings(request.PostFormValue("hcl"))
	if warnings == nil {
		warnings = []string{}
	}
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(struct {
		Warnings []string `json:"warnings"`
	}{warnings})
}
