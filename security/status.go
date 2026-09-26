//go:build darwin

package security

import (
	"fmt"

	"github.com/yokonao/appleframeworks/internal/cf"
)

// Status is an OSStatus result code of Security.framework. It can be compared
// with the Err constants through errors.Is.
type Status int32

func (s Status) Error() string {
	if load() != nil {
		return fmt.Sprintf("OSStatus %d", int32(s))
	}
	m := secCopyErrorMessageString(int32(s), 0)
	if m == 0 {
		return fmt.Sprintf("OSStatus %d", int32(s))
	}
	defer cf.CFRelease(m)
	return fmt.Sprintf("%s (OSStatus %d)", cf.GoString(m), int32(s))
}

func check(status int32) error {
	if status == 0 {
		return nil
	}
	return Status(status)
}

// fromCFError converts and releases a CFError.
func fromCFError(e cf.Ref) error {
	defer cf.CFRelease(e)
	domain, code, description := cf.ErrorInfo(e)
	if domain == "NSOSStatusErrorDomain" {
		return Status(code)
	}
	return fmt.Errorf("%s (%s %d)", description, domain, code)
}
