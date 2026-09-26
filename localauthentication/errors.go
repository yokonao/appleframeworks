//go:build darwin

package localauthentication

import (
	"fmt"

	"github.com/ebitengine/purego/objc"

	"github.com/yokonao/appleframeworks/internal/cf"
)

// Code is an LAError code. It can be compared with an *Error through errors.Is.
type Code int

const (
	ErrAuthenticationFailed  Code = -1
	ErrUserCancel            Code = -2
	ErrUserFallback          Code = -3
	ErrSystemCancel          Code = -4
	ErrPasscodeNotSet        Code = -5
	ErrBiometryNotAvailable  Code = -6
	ErrBiometryNotEnrolled   Code = -7
	ErrBiometryLockout       Code = -8
	ErrAppCancel             Code = -9
	ErrInvalidContext        Code = -10
	ErrCompanionNotAvailable Code = -11
	ErrBiometryNotPaired     Code = -12
	ErrBiometryDisconnected  Code = -13
	ErrInvalidDimensions     Code = -14
	ErrNotInteractive        Code = -1004
)

func (c Code) Error() string {
	return fmt.Sprintf("LAError %d", int(c))
}

// Error is an NSError returned by LocalAuthentication.
type Error struct {
	Domain      string
	Code        int
	Description string
}

func (e *Error) Error() string {
	return fmt.Sprintf("%s (%s %d)", e.Description, e.Domain, e.Code)
}

// Is reports whether target is the Code of an LAError.
func (e *Error) Is(target error) bool {
	c, ok := target.(Code)
	return ok && e.Domain == "com.apple.LocalAuthentication" && e.Code == int(c)
}

// fromNSError converts an NSError, which is toll-free bridged with CFError.
func fromNSError(nserror objc.ID) error {
	if nserror == 0 {
		return &Error{Domain: "com.apple.LocalAuthentication", Code: int(ErrAuthenticationFailed), Description: "unknown error"}
	}
	domain, code, description := cf.ErrorInfo(uintptr(nserror))
	return &Error{Domain: domain, Code: code, Description: description}
}
