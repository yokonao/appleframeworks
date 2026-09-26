//go:build darwin

// Package cf binds the parts of CoreFoundation that appleframeworks needs
// through purego, and provides helpers to bind other frameworks.
package cf

import (
	"errors"
	"fmt"
	"runtime"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
)

// Ref is a CFTypeRef.
type Ref = uintptr

const (
	stringEncodingUTF8 = 0x08000100
	numberSInt64Type   = 4
	numberFloat64Type  = 6
)

// ErrUnavailable reports a function or constant missing from the running macOS.
var ErrUnavailable = errors.New("not available on this macOS")

var coreFoundation uintptr

var (
	CFRetain                           func(Ref) Ref
	CFRelease                          func(Ref)
	CFGetTypeID                        func(Ref) uint
	CFCopyDescription                  func(Ref) Ref
	stringGetTypeID                    func() uint
	dataGetTypeID                      func() uint
	booleanGetTypeID                   func() uint
	numberGetTypeID                    func() uint
	dateGetTypeID                      func() uint
	arrayGetTypeID                     func() uint
	dictionaryGetTypeID                func() uint
	stringCreateWithBytes              func(alloc Ref, b *byte, n int, enc uint32, external bool) Ref
	stringCreateExternalRepresentation func(alloc, s Ref, enc uint32, lossByte uint8) Ref
	dataCreate                         func(alloc Ref, b *byte, n int) Ref
	dataGetLength                      func(Ref) int
	dataGetBytePtr                     func(Ref) *byte
	booleanGetValue                    func(Ref) bool
	numberCreate                       func(alloc Ref, typ int, value unsafe.Pointer) Ref
	numberGetValue                     func(n Ref, typ int, value unsafe.Pointer) bool
	numberIsFloatType                  func(Ref) bool
	dateCreate                         func(alloc Ref, at float64) Ref
	dateGetAbsoluteTime                func(Ref) float64
	arrayCreate                        func(alloc Ref, values *Ref, n int, callbacks uintptr) Ref
	arrayGetCount                      func(Ref) int
	arrayGetValueAtIndex               func(a Ref, i int) Ref
	dictionaryCreate                   func(alloc Ref, keys, values *Ref, n int, keyCallbacks, valueCallbacks uintptr) Ref
	dictionaryGetCount                 func(Ref) int
	dictionaryGetKeysAndValues         func(d Ref, keys, values *Ref)
	errorGetDomain                     func(Ref) Ref
	errorGetCode                       func(Ref) int
	errorCopyDescription               func(Ref) Ref

	arrayCallbacks, dictionaryKeyCallbacks, dictionaryValueCallbacks uintptr
	booleanTrue, booleanFalse                                        Ref
)

// Load opens CoreFoundation once.
var Load = sync.OnceValue(func() error {
	var err error
	if coreFoundation, err = Open("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"); err != nil {
		return err
	}
	if err := Bind(coreFoundation, map[string]any{
		"CFRetain":                             &CFRetain,
		"CFRelease":                            &CFRelease,
		"CFGetTypeID":                          &CFGetTypeID,
		"CFCopyDescription":                    &CFCopyDescription,
		"CFStringGetTypeID":                    &stringGetTypeID,
		"CFDataGetTypeID":                      &dataGetTypeID,
		"CFBooleanGetTypeID":                   &booleanGetTypeID,
		"CFNumberGetTypeID":                    &numberGetTypeID,
		"CFDateGetTypeID":                      &dateGetTypeID,
		"CFArrayGetTypeID":                     &arrayGetTypeID,
		"CFDictionaryGetTypeID":                &dictionaryGetTypeID,
		"CFStringCreateWithBytes":              &stringCreateWithBytes,
		"CFStringCreateExternalRepresentation": &stringCreateExternalRepresentation,
		"CFDataCreate":                         &dataCreate,
		"CFDataGetLength":                      &dataGetLength,
		"CFDataGetBytePtr":                     &dataGetBytePtr,
		"CFBooleanGetValue":                    &booleanGetValue,
		"CFNumberCreate":                       &numberCreate,
		"CFNumberGetValue":                     &numberGetValue,
		"CFNumberIsFloatType":                  &numberIsFloatType,
		"CFDateCreate":                         &dateCreate,
		"CFDateGetAbsoluteTime":                &dateGetAbsoluteTime,
		"CFArrayCreate":                        &arrayCreate,
		"CFArrayGetCount":                      &arrayGetCount,
		"CFArrayGetValueAtIndex":               &arrayGetValueAtIndex,
		"CFDictionaryCreate":                   &dictionaryCreate,
		"CFDictionaryGetCount":                 &dictionaryGetCount,
		"CFDictionaryGetKeysAndValues":         &dictionaryGetKeysAndValues,
		"CFErrorGetDomain":                     &errorGetDomain,
		"CFErrorGetCode":                       &errorGetCode,
		"CFErrorCopyDescription":               &errorCopyDescription,
	}); err != nil {
		return err
	}
	for name, p := range map[string]*uintptr{
		"kCFTypeArrayCallBacks":           &arrayCallbacks,
		"kCFTypeDictionaryKeyCallBacks":   &dictionaryKeyCallbacks,
		"kCFTypeDictionaryValueCallBacks": &dictionaryValueCallbacks,
	} {
		if *p, err = purego.Dlsym(coreFoundation, name); err != nil {
			return fmt.Errorf("%s is %w", name, ErrUnavailable)
		}
	}
	if booleanTrue, err = Symbol(coreFoundation, "kCFBooleanTrue"); err != nil {
		return err
	}
	booleanFalse, err = Symbol(coreFoundation, "kCFBooleanFalse")
	return err
})

// Open opens a framework. Opening the same one again returns the same handle.
func Open(path string) (uintptr, error) {
	return purego.Dlopen(path, purego.RTLD_LAZY|purego.RTLD_GLOBAL)
}

// Bind registers each C function named by a key into the function pointer
// stored as its value.
func Bind(lib uintptr, fns map[string]any) error {
	for name, fn := range fns {
		addr, err := purego.Dlsym(lib, name)
		if err != nil {
			return fmt.Errorf("%s is %w", name, ErrUnavailable)
		}
		purego.RegisterFunc(fn, addr)
	}
	return nil
}

type symbol struct {
	lib  uintptr
	name string
}

var symbols sync.Map

// Symbol returns the value of a global CFTypeRef constant such as kSecClass.
func Symbol(lib uintptr, name string) (Ref, error) {
	if ref, ok := symbols.Load(symbol{lib, name}); ok {
		return ref.(Ref), nil
	}
	addr, err := purego.Dlsym(lib, name)
	if err != nil {
		return 0, fmt.Errorf("%s is %w", name, ErrUnavailable)
	}
	ref := **(**Ref)(unsafe.Pointer(&addr))
	symbols.Store(symbol{lib, name}, ref)
	return ref, nil
}

// Object is a CoreFoundation object owned by Go and released when unreachable.
type Object struct {
	ref Ref
}

// Own takes ownership of a +1 reference.
func Own(ref Ref) *Object {
	o := &Object{ref}
	runtime.AddCleanup(o, CFRelease, ref)
	return o
}

// CFTypeRef returns the underlying CFTypeRef. The caller must keep o reachable
// while using it.
func (o *Object) CFTypeRef() uintptr {
	return o.ref
}

// String returns the CoreFoundation description of the object.
func (o *Object) String() string {
	defer runtime.KeepAlive(o)
	return Description(o.ref)
}

func IsString(r Ref) bool     { return CFGetTypeID(r) == stringGetTypeID() }
func IsData(r Ref) bool       { return CFGetTypeID(r) == dataGetTypeID() }
func IsBoolean(r Ref) bool    { return CFGetTypeID(r) == booleanGetTypeID() }
func IsNumber(r Ref) bool     { return CFGetTypeID(r) == numberGetTypeID() }
func IsDate(r Ref) bool       { return CFGetTypeID(r) == dateGetTypeID() }
func IsArray(r Ref) bool      { return CFGetTypeID(r) == arrayGetTypeID() }
func IsDictionary(r Ref) bool { return CFGetTypeID(r) == dictionaryGetTypeID() }

// The constructors below return +1 references that the caller must release.

func String(s string) Ref {
	return stringCreateWithBytes(0, unsafe.StringData(s), len(s), stringEncodingUTF8, false)
}

func Data(b []byte) Ref {
	return dataCreate(0, unsafe.SliceData(b), len(b))
}

func Boolean(b bool) Ref {
	if b {
		return CFRetain(booleanTrue)
	}
	return CFRetain(booleanFalse)
}

func Int(n int64) Ref {
	return numberCreate(0, numberSInt64Type, unsafe.Pointer(&n))
}

func Float(f float64) Ref {
	return numberCreate(0, numberFloat64Type, unsafe.Pointer(&f))
}

func Date(absoluteTime float64) Ref {
	return dateCreate(0, absoluteTime)
}

func Array(values []Ref) Ref {
	return arrayCreate(0, unsafe.SliceData(values), len(values), arrayCallbacks)
}

func Dictionary(keys, values []Ref) Ref {
	return dictionaryCreate(0, unsafe.SliceData(keys), unsafe.SliceData(values), len(keys), dictionaryKeyCallbacks, dictionaryValueCallbacks)
}

// The accessors below do not transfer ownership.

func GoString(s Ref) string {
	d := stringCreateExternalRepresentation(0, s, stringEncodingUTF8, '?')
	defer CFRelease(d)
	return string(unsafe.Slice(dataGetBytePtr(d), dataGetLength(d)))
}

func GoBytes(d Ref) []byte {
	return append([]byte{}, unsafe.Slice(dataGetBytePtr(d), dataGetLength(d))...)
}

func GoBool(b Ref) bool {
	return booleanGetValue(b)
}

// GoNumber returns an int64 or, for floating-point numbers, a float64.
func GoNumber(n Ref) any {
	if numberIsFloatType(n) {
		var f float64
		numberGetValue(n, numberFloat64Type, unsafe.Pointer(&f))
		return f
	}
	var i int64
	numberGetValue(n, numberSInt64Type, unsafe.Pointer(&i))
	return i
}

func GoAbsoluteTime(d Ref) float64 {
	return dateGetAbsoluteTime(d)
}

func ArrayValues(a Ref) []Ref {
	values := make([]Ref, arrayGetCount(a))
	for i := range values {
		values[i] = arrayGetValueAtIndex(a, i)
	}
	return values
}

func DictionaryEntries(d Ref) (keys, values []Ref) {
	n := dictionaryGetCount(d)
	keys, values = make([]Ref, n), make([]Ref, n)
	dictionaryGetKeysAndValues(d, unsafe.SliceData(keys), unsafe.SliceData(values))
	return keys, values
}

// Description returns the CoreFoundation description of any object.
func Description(r Ref) string {
	d := CFCopyDescription(r)
	defer CFRelease(d)
	return GoString(d)
}

// ErrorInfo returns the domain, code and description of a CFError.
func ErrorInfo(e Ref) (domain string, code int, description string) {
	d := errorCopyDescription(e)
	defer CFRelease(d)
	return GoString(errorGetDomain(e)), errorGetCode(e), GoString(d)
}
