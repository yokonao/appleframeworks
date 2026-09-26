//go:build darwin

package security

import (
	"reflect"
	"testing"
	"time"

	"github.com/yokonao/appleframeworks/internal/cf"
)

func TestConvertRoundTrip(t *testing.T) {
	if err := load(); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1700000000, 123000000)
	for _, tc := range []struct{ in, want any }{
		{"", ""},
		{"日本語\x00nul", "日本語\x00nul"},
		{[]byte{}, []byte{}},
		{[]byte{0, 1, 2}, []byte{0, 1, 2}},
		{true, true},
		{false, false},
		{42, int64(42)},
		{uint32(0xffffffff), int64(0xffffffff)},
		{1.5, 1.5},
		{now, now},
		{[]any{"a", 1}, []any{"a", int64(1)}},
		{Dict{"k": []byte("v")}, Dict{"k": []byte("v")}},
		{Attrs{AttrService: "s"}, Dict{"svce": "s"}},
	} {
		ref, err := toCF(tc.in)
		if err != nil {
			t.Fatalf("toCF(%#v): %v", tc.in, err)
		}
		got := fromCF(ref)
		cf.CFRelease(ref)
		if tm, ok := got.(time.Time); ok {
			if !tm.Equal(tc.want.(time.Time)) {
				t.Errorf("round trip of %v = %v", tc.in, tm)
			}
			continue
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("round trip of %#v = %#v, want %#v", tc.in, got, tc.want)
		}
	}
}

func TestConvertErrors(t *testing.T) {
	if err := load(); err != nil {
		t.Fatal(err)
	}
	if _, err := toCF(struct{}{}); err == nil {
		t.Error("toCF accepted an unsupported type")
	}
	if _, err := toCF(Attrs{Key("kSecAttrNoSuchKey"): "x"}); err == nil {
		t.Error("toCF accepted an unknown symbol")
	}
}
