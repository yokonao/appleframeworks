//go:build darwin

package security_test

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/yokonao/appleframeworks/corefoundation"
	kc "github.com/yokonao/appleframeworks/security"
	"github.com/yokonao/appleframeworks/security/legacy"
)

func item(t *testing.T) kc.Attrs {
	q := kc.Attrs{
		kc.Class:       kc.ClassGenericPassword,
		kc.AttrService: "com.github.yokonao.security.test",
		kc.AttrAccount: t.Name(),
	}
	t.Cleanup(func() { _ = kc.Delete(q) })
	return q
}

func with(q kc.Attrs, extra kc.Attrs) kc.Attrs {
	m := kc.Attrs{}
	for k, v := range q {
		m[k] = v
	}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

func TestItemLifecycle(t *testing.T) {
	q := item(t)
	if _, err := kc.CopyMatching(with(q, kc.Attrs{kc.ReturnData: true})); !errors.Is(err, kc.ErrItemNotFound) {
		t.Fatalf("CopyMatching before Add: %v", err)
	}
	if _, err := kc.Add(with(q, kc.Attrs{kc.ValueData: []byte("one"), kc.AttrLabel: "label"})); err != nil {
		t.Fatal(err)
	}
	if _, err := kc.Add(with(q, kc.Attrs{kc.ValueData: []byte("one")})); !errors.Is(err, kc.ErrDuplicateItem) {
		t.Fatalf("second Add: %v", err)
	}
	if err := kc.Update(q, kc.Attrs{kc.ValueData: []byte("two")}); err != nil {
		t.Fatal(err)
	}

	data, err := kc.CopyMatching(with(q, kc.Attrs{kc.ReturnData: true, kc.MatchLimit: kc.MatchLimitOne}))
	if err != nil || string(data.([]byte)) != "two" {
		t.Fatalf("CopyMatching data = %v, %v", data, err)
	}
	res, err := kc.CopyMatching(with(q, kc.Attrs{kc.ReturnAttributes: true, kc.MatchLimit: kc.MatchLimitAll}))
	if err != nil {
		t.Fatal(err)
	}
	attrs := res.([]any)[0].(kc.Dict)
	if v, _ := attrs.Get(kc.AttrLabel); v != "label" {
		t.Errorf("label = %v", v)
	}
	if v, _ := attrs.Get(kc.AttrAccount); v != t.Name() {
		t.Errorf("account = %v", v)
	}

	if err := kc.Delete(q); err != nil {
		t.Fatal(err)
	}
	if err := kc.Delete(q); !errors.Is(err, kc.ErrItemNotFound) {
		t.Fatalf("second Delete: %v", err)
	}
}

func TestLegacyAccess(t *testing.T) {
	q := item(t)
	keychain, err := legacy.DefaultKeychain()
	if err != nil {
		t.Fatal(err)
	}
	self, err := legacy.NewTrustedApplication("")
	if err != nil {
		t.Fatal(err)
	}
	access, err := legacy.NewAccess("appleframeworks test", self)
	if err != nil {
		t.Fatal(err)
	}
	q[kc.UseKeychain] = keychain
	if _, err := kc.Add(with(q, kc.Attrs{kc.ValueData: []byte("x"), kc.AttrAccess: access})); err != nil {
		t.Fatal(err)
	}
	ref, err := kc.CopyMatching(with(q, kc.Attrs{kc.ReturnRef: true}))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ref.(*corefoundation.Object); !ok {
		t.Fatalf("ReturnRef = %T", ref)
	}
}

func TestAccessControl(t *testing.T) {
	ac, err := kc.NewAccessControl(kc.AttrAccessibleWhenUnlockedThisDeviceOnly, kc.AccessControlUserPresence)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ac.String(), "SecAccessControl") {
		t.Errorf("description = %s", ac)
	}
}

func TestStatus(t *testing.T) {
	if msg := kc.ErrItemNotFound.Error(); !strings.Contains(msg, "-25300") || strings.HasPrefix(msg, "OSStatus") {
		t.Errorf("message = %q", msg)
	}
	if msg := kc.Status(-1).Error(); !strings.Contains(msg, "-1") {
		t.Errorf("message = %q", msg)
	}
}

func TestUnavailable(t *testing.T) {
	_, err := kc.CopyMatching(kc.Attrs{kc.Key("kSecAttrNoSuchKey"): true})
	if !errors.Is(err, kc.ErrUnavailable) {
		t.Fatalf("err = %v", err)
	}
}

// TestFirstCall runs each function as the first call of a fresh process,
// where the C functions are not bound yet.
func TestFirstCall(t *testing.T) {
	missing := kc.Attrs{kc.Class: kc.ClassGenericPassword, kc.AttrService: "com.github.yokonao.security.missing"}
	calls := map[string]func() error{
		"CopyMatching": func() error { _, err := kc.CopyMatching(missing); return err },
		"Update":       func() error { return kc.Update(missing, kc.Attrs{kc.AttrLabel: "x"}) },
		"Delete":       func() error { return kc.Delete(missing) },
	}
	if name := os.Getenv("APPLEFRAMEWORKS_FIRST_CALL"); name != "" {
		if err := calls[name](); !errors.Is(err, kc.ErrItemNotFound) {
			t.Fatalf("%s: %v", name, err)
		}
		return
	}
	for name := range calls {
		cmd := exec.Command(os.Args[0], "-test.run=^TestFirstCall$")
		cmd.Env = append(os.Environ(), "APPLEFRAMEWORKS_FIRST_CALL="+name)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("%s: %v\n%s", name, err, out)
		}
	}
}
