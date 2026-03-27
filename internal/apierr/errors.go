// Package apierr defines typed API-facing errors for the target handler -> service -> repository shape.
//
// The current codebase still routes most errors through internal/api/response directly; this package
// exists so the documented structure has a concrete home for shared API error types as the repo moves
// toward that layout.
package apierr

import (
	"errors"
	"fmt"
)

// Kind classifies an API error without coupling callers to HTTP response helpers.
type Kind string

const (
	KindBadRequest   Kind = "bad_request"
	KindUnauthorized Kind = "unauthorized"
	KindForbidden    Kind = "forbidden"
	KindNotFound     Kind = "not_found"
	KindConflict     Kind = "conflict"
	KindInternal     Kind = "internal"
)

// Error is a lightweight typed wrapper that can carry a public message and an internal cause.
type Error struct {
	Kind    Kind
	Message string
	Cause   error
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	if e.Message != "" {
		return e.Message
	}
	if e.Cause != nil {
		return e.Cause.Error()
	}
	return string(e.Kind)
}

func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// New creates a typed API error with an optional wrapped cause.
func New(kind Kind, message string, cause error) *Error {
	return &Error{
		Kind:    kind,
		Message: message,
		Cause:   cause,
	}
}

// Wrap annotates an existing error as an API error. Nil input stays nil.
func Wrap(kind Kind, message string, err error) error {
	if err == nil {
		return nil
	}
	return New(kind, message, err)
}

// IsKind reports whether err or any wrapped error is an *Error with the given kind.
func IsKind(err error, kind Kind) bool {
	var apiErr *Error
	if !errors.As(err, &apiErr) {
		return false
	}
	return apiErr.Kind == kind
}

func (k Kind) String() string {
	return string(k)
}

func (e *Error) Format(s fmt.State, verb rune) {
	switch verb {
	case 'v':
		if s.Flag('+') && e.Cause != nil {
			_, _ = fmt.Fprintf(s, "%s: %v", e.Error(), e.Cause)
			return
		}
		fallthrough
	case 's':
		_, _ = fmt.Fprint(s, e.Error())
	case 'q':
		_, _ = fmt.Fprintf(s, "%q", e.Error())
	}
}
