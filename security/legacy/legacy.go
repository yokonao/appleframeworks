//go:build darwin

// Package legacy binds the deprecated APIs of the file-based macOS keychain,
// which still work without the keychain-access-groups entitlement that
// ad-hoc signed binaries cannot carry. They are isolated here so that their
// removal by Apple affects only this package.
//
// Pass the objects as values of security.UseKeychain and
// security.AttrAccess.
package legacy

import (
	"runtime"
	"sync"

	"github.com/yokonao/appleframeworks/corefoundation"
	"github.com/yokonao/appleframeworks/internal/cf"
	"github.com/yokonao/appleframeworks/security"
)

var (
	secKeychainCopyDefault              func(keychain *cf.Ref) int32
	secTrustedApplicationCreateFromPath func(path *byte, app *cf.Ref) int32
	secAccessCreate                     func(descriptor, trustedList cf.Ref, access *cf.Ref) int32
)

var load = sync.OnceValue(func() error {
	if err := cf.Load(); err != nil {
		return err
	}
	security, err := cf.Open("/System/Library/Frameworks/Security.framework/Security")
	if err != nil {
		return err
	}
	return cf.Bind(security, map[string]any{
		"SecKeychainCopyDefault":              &secKeychainCopyDefault,
		"SecTrustedApplicationCreateFromPath": &secTrustedApplicationCreateFromPath,
		"SecAccessCreate":                     &secAccessCreate,
	})
})

func create(fn func(*cf.Ref) int32) (*corefoundation.Object, error) {
	if err := load(); err != nil {
		return nil, err
	}
	var ref cf.Ref
	if status := fn(&ref); status != 0 {
		return nil, security.Status(status)
	}
	return cf.Own(ref), nil
}

// DefaultKeychain calls SecKeychainCopyDefault.
func DefaultKeychain() (*corefoundation.Object, error) {
	return create(func(keychain *cf.Ref) int32 {
		return secKeychainCopyDefault(keychain)
	})
}

// NewTrustedApplication calls SecTrustedApplicationCreateFromPath. An empty
// path means the running binary.
func NewTrustedApplication(path string) (*corefoundation.Object, error) {
	return create(func(app *cf.Ref) int32 {
		if path == "" {
			return secTrustedApplicationCreateFromPath(nil, app)
		}
		p := append([]byte(path), 0)
		return secTrustedApplicationCreateFromPath(&p[0], app)
	})
}

// NewAccess calls SecAccessCreate. Without trusted applications, only the
// running binary is trusted.
func NewAccess(descriptor string, trusted ...*corefoundation.Object) (*corefoundation.Object, error) {
	return create(func(access *cf.Ref) int32 {
		d := cf.String(descriptor)
		defer cf.CFRelease(d)
		var list cf.Ref
		if len(trusted) > 0 {
			refs := make([]cf.Ref, len(trusted))
			for i, t := range trusted {
				refs[i] = t.Pointer()
			}
			list = cf.Array(refs)
			defer cf.CFRelease(list)
			defer runtime.KeepAlive(trusted)
		}
		return secAccessCreate(d, list, access)
	})
}
