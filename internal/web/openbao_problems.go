// ---
// relationships:
//   implements: web-interface
//   uses: controller
// ---

package web

import "github.com/wyrd-company/wyrwood/internal/openbao"

// openBaoDidNotAnswer is the keys page message for an OpenBao that gave no
// answer to a list.
const openBaoDidNotAnswer = "OpenBao did not answer. The lists below may be incomplete; agents keep serving containers."

// openBaoProblem names the category of an OpenBao failure that got an answer,
// for an operator message. It carries no upstream text.
func openBaoProblem(err error) string {
	switch openbao.CategoryOf(err) {
	case openbao.CategoryDenied:
		return "permission refused"
	case openbao.CategoryNotFound:
		return "not found"
	default:
		return "OpenBao answered with an error"
	}
}

// unreadableTransitKeyProblems names each listed Transit key that could not be
// read and why, each message followed by suffix.
func unreadableTransitKeyProblems(listing openbao.TransitKeyListing, suffix string) []string {
	problems := make([]string, 0, len(listing.Unreadable))
	for _, key := range listing.Unreadable {
		problems = append(problems, "Transit key "+key.Name+" could not be read: "+openBaoProblem(key.Err)+"."+suffix)
	}
	return problems
}
