// ---
// relationships:
//   implements: operator-interface
// ---

package operator

import "errors"

// Errors a client can act on. Every failure of Dial, Login, or a request wraps
// one of them or is an *Error with one of them as its code.
var (
	// ErrInvalidURL means the controller URL is not ssh://host[:port].
	ErrInvalidURL = errors.New("controller URL is invalid")
	// ErrUnreachable means no SSH session could be opened or kept.
	ErrUnreachable = errors.New("controller unreachable")
	// ErrHostKeyMismatch means the controller presented another host key.
	ErrHostKeyMismatch = errors.New("controller host-key fingerprint does not match")
	// ErrHostKeyNotAccepted means nobody accepted the controller's host key.
	ErrHostKeyNotAccepted = errors.New("controller host-key fingerprint was not accepted")
	// ErrKeySelection means no single key matches the selection.
	ErrKeySelection = errors.New("no single SSH agent key matches the selection")
	// ErrLoginState means the key or the saved login could not be read or written.
	ErrLoginState = errors.New("operator key or login state unavailable")
	// ErrNotApproved means the key is pending, rejected, or revoked.
	ErrNotApproved = errors.New("operator key is not approved")
	// ErrOutsideGrant means the key's grant does not cover the request.
	ErrOutsideGrant = errors.New("outside this key's grant")
	// ErrNotFound means the policy or binding does not exist.
	ErrNotFound = errors.New("not found")
	// ErrBindingDiffers means the container key is bound to another selection.
	ErrBindingDiffers = errors.New("the container key is bound to another selection")
	// ErrInvalid means the controller refused the request's content.
	ErrInvalid = errors.New("invalid request")
	// ErrPending means the change is saved and OpenBao has not applied it yet.
	// Repeat the request to finish it.
	ErrPending = errors.New("saved; OpenBao has not applied the change")
	// ErrFailed means the controller could not do the request.
	ErrFailed = errors.New("operation failed")
)

// Code is the closed vocabulary of request failures on the wire.
type Code string

const (
	CodeNotApproved   Code = "not-approved"
	CodeOutsideGrant  Code = "outside-grant"
	CodeNotFound      Code = "not-found"
	CodeBindingDiffer Code = "binding-differs"
	CodeInvalid       Code = "invalid"
	CodePending       Code = "pending"
	CodeFailed        Code = "failed"
)

var codeErrors = map[Code]error{
	CodeNotApproved: ErrNotApproved, CodeOutsideGrant: ErrOutsideGrant, CodeNotFound: ErrNotFound,
	CodeBindingDiffer: ErrBindingDiffers, CodeInvalid: ErrInvalid, CodePending: ErrPending, CodeFailed: ErrFailed,
}

// Error is a failure the controller reported. errors.Is matches its code's
// sentinel error.
type Error struct {
	Code    Code   `json:"code"`
	Message string `json:"message"`
	// Part is the part of the request the failure is about, when one part owns it.
	Part string `json:"part,omitempty"`
}

func (err *Error) Error() string { return err.Message }

// Is matches the sentinel error of the failure's code. An unknown code matches
// ErrFailed.
func (err *Error) Is(target error) bool {
	sentinel, known := codeErrors[err.Code]
	if !known {
		sentinel = ErrFailed
	}
	return target == sentinel
}
