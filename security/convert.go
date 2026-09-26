//go:build darwin

package security

import (
	"fmt"
	"runtime"
	"time"

	"github.com/yokonao/appleframeworks/internal/cf"
)

// absoluteTimeEpoch is the Unix time of CoreFoundation's reference date, 2001-01-01.
const absoluteTimeEpoch = 978307200

// Dict is a dictionary returned by Keychain Services. It is keyed by the values
// of the key constants, which are short strings such as "svce".
type Dict map[string]any

// Get returns the value for k.
func (d Dict) Get(k Key) (any, bool) {
	if load() != nil {
		return nil, false
	}
	ref, err := cf.Symbol(lib, string(k))
	if err != nil {
		return nil, false
	}
	v, ok := d[cf.GoString(ref)]
	return v, ok
}

// toCF returns a +1 reference that the caller must release.
func toCF(v any) (cf.Ref, error) {
	switch v := v.(type) {
	case string:
		return cf.String(v), nil
	case []byte:
		return cf.Data(v), nil
	case bool:
		return cf.Boolean(v), nil
	case int:
		return cf.Int(int64(v)), nil
	case int8:
		return cf.Int(int64(v)), nil
	case int16:
		return cf.Int(int64(v)), nil
	case int32:
		return cf.Int(int64(v)), nil
	case int64:
		return cf.Int(v), nil
	case uint8:
		return cf.Int(int64(v)), nil
	case uint16:
		return cf.Int(int64(v)), nil
	case uint32:
		return cf.Int(int64(v)), nil
	case float32:
		return cf.Float(float64(v)), nil
	case float64:
		return cf.Float(v), nil
	case time.Time:
		return cf.Date(float64(v.UnixNano())/1e9 - absoluteTimeEpoch), nil
	case Constant:
		ref, err := cf.Symbol(lib, string(v))
		if err != nil {
			return 0, err
		}
		return cf.CFRetain(ref), nil
	case *cf.Object:
		defer runtime.KeepAlive(v)
		return cf.CFRetain(v.Pointer()), nil
	case []any:
		refs, err := toCFs(v)
		if err != nil {
			return 0, err
		}
		defer releaseAll(refs)
		return cf.Array(refs), nil
	case Attrs:
		keys := make([]any, 0, len(v))
		values := make([]any, 0, len(v))
		for k, val := range v {
			keys = append(keys, Constant(k))
			values = append(values, val)
		}
		return dictionary(keys, values)
	case Dict:
		keys := make([]any, 0, len(v))
		values := make([]any, 0, len(v))
		for k, val := range v {
			keys = append(keys, k)
			values = append(values, val)
		}
		return dictionary(keys, values)
	default:
		return 0, fmt.Errorf("security: unsupported value type %T", v)
	}
}

func dictionary(keys, values []any) (cf.Ref, error) {
	k, err := toCFs(keys)
	if err != nil {
		return 0, err
	}
	defer releaseAll(k)
	vals, err := toCFs(values)
	if err != nil {
		return 0, err
	}
	defer releaseAll(vals)
	return cf.Dictionary(k, vals), nil
}

func toCFs(values []any) ([]cf.Ref, error) {
	refs := make([]cf.Ref, 0, len(values))
	for _, v := range values {
		ref, err := toCF(v)
		if err != nil {
			releaseAll(refs)
			return nil, err
		}
		refs = append(refs, ref)
	}
	return refs, nil
}

func releaseAll(refs []cf.Ref) {
	for _, r := range refs {
		cf.CFRelease(r)
	}
}

// fromCF does not take ownership of r.
func fromCF(r cf.Ref) any {
	switch {
	case cf.IsString(r):
		return cf.GoString(r)
	case cf.IsData(r):
		return cf.GoBytes(r)
	case cf.IsBoolean(r):
		return cf.GoBool(r)
	case cf.IsNumber(r):
		return cf.GoNumber(r)
	case cf.IsDate(r):
		sec := cf.GoAbsoluteTime(r) + absoluteTimeEpoch
		return time.Unix(0, int64(sec*1e9)).Round(time.Microsecond)
	case cf.IsArray(r):
		refs := cf.ArrayValues(r)
		values := make([]any, len(refs))
		for i, ref := range refs {
			values[i] = fromCF(ref)
		}
		return values
	case cf.IsDictionary(r):
		keys, values := cf.DictionaryEntries(r)
		d := make(Dict, len(keys))
		for i, k := range keys {
			name := cf.Description(k)
			if cf.IsString(k) {
				name = cf.GoString(k)
			}
			d[name] = fromCF(values[i])
		}
		return d
	default:
		return cf.Own(cf.CFRetain(r))
	}
}
