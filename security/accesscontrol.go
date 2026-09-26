//go:build darwin

package security

import (
	"github.com/yokonao/appleframeworks/corefoundation"
	"github.com/yokonao/appleframeworks/internal/cf"
)

// AccessControlFlags is SecAccessControlCreateFlags.
type AccessControlFlags uint

const (
	AccessControlUserPresence        AccessControlFlags = 1 << 0
	AccessControlBiometryAny         AccessControlFlags = 1 << 1
	AccessControlBiometryCurrentSet  AccessControlFlags = 1 << 3
	AccessControlDevicePasscode      AccessControlFlags = 1 << 4
	AccessControlCompanion           AccessControlFlags = 1 << 5
	AccessControlOr                  AccessControlFlags = 1 << 14
	AccessControlAnd                 AccessControlFlags = 1 << 15
	AccessControlPrivateKeyUsage     AccessControlFlags = 1 << 30
	AccessControlApplicationPassword AccessControlFlags = 1 << 31
)

// NewAccessControl calls SecAccessControlCreateWithFlags. Pass the result as
// the value of AttrAccessControl. protection is one of the AttrAccessible
// constants.
func NewAccessControl(protection Constant, flags AccessControlFlags) (*corefoundation.Object, error) {
	if err := load(); err != nil {
		return nil, err
	}
	p, err := toCF(protection)
	if err != nil {
		return nil, err
	}
	defer cf.CFRelease(p)
	var e cf.Ref
	ac := secAccessControlCreateWithFlags(0, p, uint(flags), &e)
	if ac == 0 {
		return nil, fromCFError(e)
	}
	return cf.Own(ac), nil
}
