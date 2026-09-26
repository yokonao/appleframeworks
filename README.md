# appleframeworks

cgo-free Go bindings for Apple frameworks, built on [purego](https://github.com/ebitengine/purego).
Binaries can be built with `CGO_ENABLED=0` and cross-compiled for macOS from any OS.

This is an unofficial project and is not affiliated with Apple. It supports macOS only;
other platforms fail to compile.

## Packages

| Package | Framework |
|---|---|
| `corefoundation` | CoreFoundation objects shared by the other packages |
| `security` | Keychain Services (`SecItemAdd`, `SecItemCopyMatching`, `SecItemUpdate`, `SecItemDelete`, `SecAccessControl`) |
| `localauthentication` | LocalAuthentication (`LAContext`) for Touch ID and device password prompts |
| `security/legacy` | Deprecated APIs of the file-based keychain (`SecKeychain`, `SecAccess`, `SecTrustedApplication`) |

## Usage

```go
import "github.com/yokonao/appleframeworks/security"

_, err := security.Add(security.Attrs{
	security.Class:       security.ClassGenericPassword,
	security.AttrService: "com.example.app",
	security.AttrAccount: "token",
	security.ValueData:   []byte("secret"),
})

data, err := security.CopyMatching(security.Attrs{
	security.Class:       security.ClassGenericPassword,
	security.AttrService: "com.example.app",
	security.AttrAccount: "token",
	security.ReturnData:  true,
	security.MatchLimit:  security.MatchLimitOne,
})
if errors.Is(err, security.ErrItemNotFound) {
	// ...
}
secret := data.([]byte)
```

The API mirrors the C API: queries are dictionaries keyed by the same constants,
and results take the shape the query asks for. See the package documentation for
how values are converted between Go and CoreFoundation.

Keychain constants hold their symbol names and are resolved at run time. A constant this
module does not define yet can be used as `security.Key("kSecAttrXxx")`, and one
missing from the running macOS returns `security.ErrUnavailable`.

```go
import la "github.com/yokonao/appleframeworks/localauthentication"

c, err := la.NewContext()
err = c.EvaluatePolicy(la.PolicyDeviceOwnerAuthenticationWithBiometrics, "unlock the vault")
if errors.Is(err, la.ErrUserCancel) {
	// ...
}
```

## Development

The constants in `security/symbols.go` and `security/errors.go` are generated from
the headers of the installed macOS SDK:

```sh
go generate ./...
```

Tests add and remove items in the login keychain. `LA_MANUAL=1 go test -run Manual ./localauthentication` shows a Touch ID prompt.
