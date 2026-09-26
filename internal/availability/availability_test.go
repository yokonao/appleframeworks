// Package availability checks every framework symbol the module references
// against the availability annotations of the installed macOS SDK.
package availability

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"maps"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// minimum is the oldest macOS that Go 1.26 runs on.
const minimum = "12.0"

// newer lists the symbols that need a macOS newer than minimum. Keep the table
// in README.md in sync.
var newer = map[string]string{
	"kSecMatchHostOrSubdomainOfHost": "15.0",
}

var receivers = map[string]string{
	"new":   "LAContext",
	"drain": "(NSAutoreleasePool *)0",
}

var (
	symbolRe    = regexp.MustCompile(`^k?(CF|Sec)[A-Za-z0-9]+$`)
	availableRe = regexp.MustCompile(`'([^']+)' is only available on macOS ([0-9.]+) or newer`)
	diagRe      = regexp.MustCompile(`(warning|error): (.*)`)
)

func TestAvailability(t *testing.T) {
	if _, err := exec.LookPath("xcrun"); err != nil {
		t.Skip("requires the macOS SDK")
	}
	src := source(t)
	cmd := exec.Command("xcrun", "clang", "-fsyntax-only", "-x", "objective-c", "-",
		"-mmacosx-version-min="+minimum, "-Wunguarded-availability",
		"-Wno-nonnull", "-Wno-deprecated-declarations", "-Wno-unused-value")
	cmd.Stdin = strings.NewReader(src)
	out, _ := cmd.CombinedOutput()

	got := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		if m := availableRe.FindStringSubmatch(line); m != nil {
			got[m[1]] = m[2]
		} else if m := diagRe.FindStringSubmatch(line); m != nil {
			t.Errorf("%s\n%s", m[0], src)
		}
	}
	if !maps.Equal(got, newer) {
		t.Errorf("symbols newer than macOS %s = %v, want %v", minimum, got, newer)
	}
}

// source returns Objective-C that references every framework symbol, class and
// selector named in the non-test Go files of the module.
func source(t *testing.T) string {
	var b strings.Builder
	b.WriteString("#import <Foundation/Foundation.h>\n#import <LocalAuthentication/LocalAuthentication.h>\n#import <Security/Security.h>\nvoid f(void) {\n")
	err := filepath.WalkDir("../..", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && len(call.Args) == 1 {
					if name, ok := literal(call.Args[0]); ok {
						switch sel.Sel.Name {
						case "GetClass":
							fmt.Fprintf(&b, "[%s class];\n", name)
						case "RegisterName":
							b.WriteString(send(name))
						}
					}
				}
			}
			if name, ok := literal(n); ok && symbolRe.MatchString(name) {
				fmt.Fprintf(&b, "(void)%s;\n", name)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	b.WriteString("}\n")
	return b.String()
}

func literal(n ast.Node) (string, bool) {
	lit, ok := n.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(lit.Value)
	return s, err == nil
}

// send returns a message send of selector with every argument 0.
func send(selector string) string {
	receiver := receivers[selector]
	if receiver == "" {
		receiver = "(LAContext *)0"
	}
	msg := selector
	if strings.Contains(selector, ":") {
		msg = strings.ReplaceAll(strings.TrimSuffix(selector, ":"), ":", ":0 ") + ":0"
	}
	return fmt.Sprintf("[%s %s];\n", receiver, msg)
}
