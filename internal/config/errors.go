// ---
// relationships: {}
// ---

package config

import "fmt"

// FieldError reports a configuration problem at its durable field location.
type FieldError struct {
	Field   string
	Line    int
	Column  int
	Problem string
}

func (e *FieldError) Error() string {
	location := e.Field
	if location == "" {
		location = "configuration"
	}
	if e.Line > 0 {
		return fmt.Sprintf("%s (line %d, column %d): %s", location, e.Line, e.Column, e.Problem)
	}
	return fmt.Sprintf("%s: %s", location, e.Problem)
}

func fieldError(field, problem string) error {
	return &FieldError{Field: field, Problem: problem}
}
