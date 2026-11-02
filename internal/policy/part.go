// ---
// relationships:
//   implements: policy
// ---

package policy

import (
	"errors"
	"fmt"
)

// Part is the part of a policy or a binding that a validation problem is about.
type Part string

const (
	PartName      Part = "name"
	PartOpenBao   Part = "openbao"
	PartSSH       Part = "ssh"
	PartContract  Part = "contract"
	PartKey       Part = "key"
	PartSelection Part = "selection"
	PartSettings  Part = "settings"
)

// PartError is a validation problem and the part it is about, so that a caller
// can place the problem without reading its text.
type PartError struct {
	Part    Part
	Message string
}

func (err *PartError) Error() string { return err.Message }

func partError(part Part, format string, arguments ...any) error {
	return &PartError{Part: part, Message: fmt.Sprintf(format, arguments...)}
}

// PartOf returns the part an error is about, or an empty part when it names none.
func PartOf(err error) Part {
	var located *PartError
	if errors.As(err, &located) {
		return located.Part
	}
	return ""
}
