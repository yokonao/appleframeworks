//go:build darwin

// Package security binds Keychain Services of Apple's Security framework
// (SecItemAdd, SecItemCopyMatching, SecItemUpdate and SecItemDelete) without cgo.
//
// It works only on macOS. Queries and attributes are dictionaries keyed by the
// same constants as in C. Constants hold their symbol names and are resolved at
// run time, so a key missing from this package can be used as Key("kSecAttrXxx")
// and a key missing from the running macOS yields ErrUnavailable instead of a crash.
//
// Values are converted between Go and CoreFoundation as follows:
//
//	string       CFString
//	[]byte       CFData
//	bool         CFBoolean
//	int*, uint*  CFNumber (int64 when read back)
//	float*       CFNumber (float64 when read back)
//	time.Time    CFDate
//	[]any        CFArray
//	Attrs, Dict  CFDictionary (Dict when read back)
//	Constant     the constant it names
//	CFTypeRef()  any other object, such as *Object or *localauthentication.Context
//	             (*Object when read back)
package security

import (
	"sync"

	"github.com/yokonao/appleframeworks/internal/cf"
)

//go:generate go run ../internal/gen

// Key is the symbol name of a dictionary key constant, such as "kSecAttrService".
type Key string

// Constant is the symbol name of a value constant, such as "kSecClassGenericPassword".
type Constant string

// Object is a CoreFoundation object, such as a SecAccessControlRef. It is
// released when it becomes unreachable.
type Object = cf.Object

// Attrs is a query or attribute dictionary passed to Keychain Services.
type Attrs map[Key]any

// ErrUnavailable reports a function or constant missing from the running macOS.
var ErrUnavailable = cf.ErrUnavailable

var (
	secItemAdd                      func(attrs cf.Ref, result *cf.Ref) int32
	secItemCopyMatching             func(query cf.Ref, result *cf.Ref) int32
	secItemUpdate                   func(query, attrs cf.Ref) int32
	secItemDelete                   func(query cf.Ref) int32
	secCopyErrorMessageString       func(status int32, reserved uintptr) cf.Ref
	secAccessControlCreateWithFlags func(alloc, protection cf.Ref, flags uint, err *cf.Ref) cf.Ref
)

var lib uintptr

var load = sync.OnceValue(func() error {
	if err := cf.Load(); err != nil {
		return err
	}
	var err error
	if lib, err = cf.Open("/System/Library/Frameworks/Security.framework/Security"); err != nil {
		return err
	}
	return cf.Bind(lib, map[string]any{
		"SecItemAdd":                      &secItemAdd,
		"SecItemCopyMatching":             &secItemCopyMatching,
		"SecItemUpdate":                   &secItemUpdate,
		"SecItemDelete":                   &secItemDelete,
		"SecCopyErrorMessageString":       &secCopyErrorMessageString,
		"SecAccessControlCreateWithFlags": &secAccessControlCreateWithFlags,
	})
})

// Add calls SecItemAdd. The result is nil unless attrs requests one with a
// Return key.
func Add(attrs Attrs) (any, error) {
	return withResult(attrs, &secItemAdd)
}

// CopyMatching calls SecItemCopyMatching. The result depends on the Return and
// MatchLimit keys of query, as in C.
func CopyMatching(query Attrs) (any, error) {
	return withResult(query, &secItemCopyMatching)
}

// Update calls SecItemUpdate.
func Update(query, attrs Attrs) error {
	if err := load(); err != nil {
		return err
	}
	q, err := toCF(query)
	if err != nil {
		return err
	}
	defer cf.CFRelease(q)
	a, err := toCF(attrs)
	if err != nil {
		return err
	}
	defer cf.CFRelease(a)
	return check(secItemUpdate(q, a))
}

// Delete calls SecItemDelete.
func Delete(query Attrs) error {
	if err := load(); err != nil {
		return err
	}
	q, err := toCF(query)
	if err != nil {
		return err
	}
	defer cf.CFRelease(q)
	return check(secItemDelete(q))
}

// call is a pointer because the function is bound by load.
func withResult(attrs Attrs, call *func(cf.Ref, *cf.Ref) int32) (any, error) {
	if err := load(); err != nil {
		return nil, err
	}
	d, err := toCF(attrs)
	if err != nil {
		return nil, err
	}
	defer cf.CFRelease(d)
	var result cf.Ref
	if err := check((*call)(d, &result)); err != nil {
		return nil, err
	}
	if result == 0 {
		return nil, nil
	}
	defer cf.CFRelease(result)
	return fromCF(result), nil
}
