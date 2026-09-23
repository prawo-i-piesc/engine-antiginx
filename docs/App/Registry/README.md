# Registry

`App/Registry` holds the built-in `SiteTests.Test` implementations. Its `init()` registers 17 tests: HTTPS, HSTS, server header, CSP, cookie security, JavaScript obfuscation, X-Frame, referrer policy, permissions policy, X-Content-Type-Options, SSL certificate, cross-origin headers, sitemap security, phishing URL, bot protection, DNS reputation, and favicon origin. Each is created by its package's `New()` function. See [Site Tests](../SiteTests/README.md) for the test framework and execution phases.

## API and lifecycle

| Function | Behavior |
|---|---|
| `GetTest(testId string) (SiteTests.Test, bool)` | Looks up an ID in the internal map; returns `nil, false` for an unknown ID. Call `GetKind()` on a found test to determine its phase. |
| `GetAllTests() []SiteTests.Test` | Returns a new slice containing all registered tests. Order is unspecified (map iteration). |
| `GetTestsByKind(kind SiteTests.TestKind) []SiteTests.Test` | Returns a new slice filtered by execution phase; empty if none match. Order is unspecified. |
| `registerTest(t SiteTests.Test)` | Package-private registration; panics with `Errors.Error` code 100 on a duplicate `GetId()`. |

To add a built-in test, add its constructor call to `init()` in `App/Registry/test_registry.go`; `registerTest` is not callable from other packages. Registration happens during package initialization, before callers use the exported lookup functions. Lookups are map reads (average constant time); `GetAllTests` and `GetTestsByKind` traverse the entire map.

The map has no mutex. Concurrent lookups after initialization are fine, but the package does **not** provide a general thread-safe, dynamically writable registry. Returned slices are independent containers, but their elements reference the registered test instances; callers should not assume tests themselves are safe to mutate concurrently. `GetTest` does not run the test.
