//go:build darwin

// Package corefoundation provides the CoreFoundation object shared by the
// other packages of appleframeworks.
package corefoundation

import "github.com/yokonao/appleframeworks/internal/cf"

// Object is a CoreFoundation object, such as a SecAccessControlRef. It is
// released when it becomes unreachable.
type Object = cf.Object

// Retain wraps a CoreFoundation object created elsewhere, such as through
// purego/objc. It retains p, so the caller keeps its own reference.
func Retain(p uintptr) (*Object, error) {
	if err := cf.Load(); err != nil {
		return nil, err
	}
	return cf.Own(cf.CFRetain(p)), nil
}
