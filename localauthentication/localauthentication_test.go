//go:build darwin

package localauthentication_test

import (
	"errors"
	"os"
	"testing"

	la "github.com/yokonao/appleframeworks/localauthentication"
)

func TestCanEvaluatePolicy(t *testing.T) {
	c, err := la.NewContext()
	if err != nil {
		t.Fatal(err)
	}
	c.SetLocalizedCancelTitle("Cancel")
	c.SetLocalizedFallbackTitle("")
	c.SetTouchIDAuthenticationAllowableReuseDuration(0)
	err = c.CanEvaluatePolicy(la.PolicyDeviceOwnerAuthenticationWithBiometrics)
	var e *la.Error
	if err != nil && !errors.As(err, &e) {
		t.Fatalf("CanEvaluatePolicy = %v", err)
	}
	t.Log(err)
}

func TestInvalidatedContext(t *testing.T) {
	c, err := la.NewContext()
	if err != nil {
		t.Fatal(err)
	}
	c.Invalidate()
	if err := c.EvaluatePolicy(la.PolicyDeviceOwnerAuthentication, "test"); !errors.Is(err, la.ErrInvalidContext) {
		t.Fatalf("EvaluatePolicy on an invalidated context = %v", err)
	}
}

// Shows a Touch ID prompt: LA_MANUAL=1 go test -run Manual ./localauthentication
func TestManualEvaluatePolicy(t *testing.T) {
	if os.Getenv("LA_MANUAL") == "" {
		t.Skip("set LA_MANUAL=1 to show the prompt")
	}
	c, err := la.NewContext()
	if err != nil {
		t.Fatal(err)
	}
	t.Log(c.EvaluatePolicy(la.PolicyDeviceOwnerAuthenticationWithBiometrics, "test appleframeworks"))
}
