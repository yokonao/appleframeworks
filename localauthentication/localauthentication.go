//go:build darwin

// Package localauthentication binds LAContext of Apple's LocalAuthentication
// framework without cgo, to authenticate the user with Touch ID or the
// device password.
//
// It works only on macOS.
package localauthentication

import (
	"fmt"
	"runtime"
	"sync"
	"time"

	"github.com/ebitengine/purego/objc"

	"github.com/yokonao/appleframeworks/internal/cf"
)

// Policy is an LAPolicy.
type Policy int

const (
	PolicyDeviceOwnerAuthenticationWithBiometrics            Policy = 1
	PolicyDeviceOwnerAuthentication                          Policy = 2
	PolicyDeviceOwnerAuthenticationWithCompanion             Policy = 3
	PolicyDeviceOwnerAuthenticationWithBiometricsOrCompanion Policy = 4
)

// ErrUnavailable reports a function or class missing from the running macOS.
var ErrUnavailable = cf.ErrUnavailable

var load = sync.OnceValue(func() error {
	if err := cf.Load(); err != nil {
		return err
	}
	if _, err := cf.Open("/System/Library/Frameworks/LocalAuthentication.framework/LocalAuthentication"); err != nil {
		return err
	}
	if objc.GetClass("LAContext") == 0 {
		return fmt.Errorf("LAContext is %w", ErrUnavailable)
	}
	return nil
})

var (
	selNew                  = objc.RegisterName("new")
	selRelease              = objc.RegisterName("release")
	selInvalidate           = objc.RegisterName("invalidate")
	selSetCancelTitle       = objc.RegisterName("setLocalizedCancelTitle:")
	selSetFallbackTitle     = objc.RegisterName("setLocalizedFallbackTitle:")
	selSetReuseDuration     = objc.RegisterName("setTouchIDAuthenticationAllowableReuseDuration:")
	selCanEvaluatePolicy    = objc.RegisterName("canEvaluatePolicy:error:")
	selEvaluatePolicy       = objc.RegisterName("evaluatePolicy:localizedReason:reply:")
	selAutoreleasePoolDrain = objc.RegisterName("drain")
)

// Context is an LAContext. It is released when it becomes unreachable.
type Context struct {
	id objc.ID
}

// NewContext creates an LAContext.
func NewContext() (*Context, error) {
	if err := load(); err != nil {
		return nil, err
	}
	c := &Context{objc.ID(objc.GetClass("LAContext")).Send(selNew)}
	runtime.AddCleanup(c, func(id objc.ID) { id.Send(selRelease) }, c.id)
	return c, nil
}

// Pointer returns the underlying LAContext, such as for kSecUseAuthenticationContext.
// The caller must keep c reachable while using it.
func (c *Context) Pointer() uintptr {
	return uintptr(c.id)
}

// setString sends a setter taking an NSString, which is toll-free bridged with CFString.
func (c *Context) setString(sel objc.SEL, s string) {
	str := cf.String(s)
	defer cf.CFRelease(str)
	c.id.Send(sel, str)
	runtime.KeepAlive(c)
}

// SetLocalizedCancelTitle sets localizedCancelTitle.
func (c *Context) SetLocalizedCancelTitle(title string) {
	c.setString(selSetCancelTitle, title)
}

// SetLocalizedFallbackTitle sets localizedFallbackTitle. An empty title hides
// the fallback button.
func (c *Context) SetLocalizedFallbackTitle(title string) {
	c.setString(selSetFallbackTitle, title)
}

// SetTouchIDAuthenticationAllowableReuseDuration sets
// touchIDAuthenticationAllowableReuseDuration.
func (c *Context) SetTouchIDAuthenticationAllowableReuseDuration(d time.Duration) {
	c.id.Send(selSetReuseDuration, d.Seconds())
	runtime.KeepAlive(c)
}

// Invalidate calls invalidate, which cancels a pending evaluation.
func (c *Context) Invalidate() {
	c.id.Send(selInvalidate)
	runtime.KeepAlive(c)
}

// CanEvaluatePolicy calls canEvaluatePolicy:error: and returns nil when the
// policy can be evaluated.
func (c *Context) CanEvaluatePolicy(policy Policy) error {
	defer runtime.KeepAlive(c)
	pool := objc.ID(objc.GetClass("NSAutoreleasePool")).Send(selNew)
	defer pool.Send(selAutoreleasePoolDrain)
	var nserror objc.ID
	if objc.Send[bool](c.id, selCanEvaluatePolicy, policy, &nserror) {
		return nil
	}
	return fromNSError(nserror)
}

// EvaluatePolicy calls evaluatePolicy:localizedReason:reply: and waits for the
// reply. It returns nil when the user is authenticated.
func (c *Context) EvaluatePolicy(policy Policy, reason string) error {
	defer runtime.KeepAlive(c)
	r := cf.String(reason)
	defer cf.CFRelease(r)
	result := make(chan error, 1)
	reply := objc.NewBlock(func(_ objc.Block, ok bool, nserror objc.ID) {
		if ok {
			result <- nil
		} else {
			result <- fromNSError(nserror)
		}
	})
	defer reply.Release()
	c.id.Send(selEvaluatePolicy, policy, r, reply)
	return <-result
}
