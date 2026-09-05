// Package Registry provides a thread-safe, centralized registry system for managing
// security test implementations. It acts as a repository for all available tests of every
// kind, enabling dynamic test retrieval and execution throughout the application.
//
// The registry automatically initializes with default tests during package initialization
// and enforces uniqueness of test IDs to prevent conflicts. All tests are indexed by
// their string identifiers for fast O(1) lookup operations.
//
// Error codes:
//   - 100: Duplicate test ID detected during registration
package Registry

import (
	error "Engine-AntiGinx/App/Errors"
	"Engine-AntiGinx/App/SiteTests"
	"Engine-AntiGinx/App/SiteTests/BotProtectionTest"
	"Engine-AntiGinx/App/SiteTests/CSPTest"
	"Engine-AntiGinx/App/SiteTests/CookieSecurityTest"
	"Engine-AntiGinx/App/SiteTests/CrossOriginTest"
	"Engine-AntiGinx/App/SiteTests/HSTSTest"
	"Engine-AntiGinx/App/SiteTests/HTTPSTest"
	"Engine-AntiGinx/App/SiteTests/JSObfuscationTest"
	"Engine-AntiGinx/App/SiteTests/PermissionsPolicyTest"
	"Engine-AntiGinx/App/SiteTests/PhishingURLTest"
	"Engine-AntiGinx/App/SiteTests/ReferrerPolicyTest"
	"Engine-AntiGinx/App/SiteTests/SSLCertificateSecurityTest"
	"Engine-AntiGinx/App/SiteTests/ServerHeaderTest"
	"Engine-AntiGinx/App/SiteTests/SitemapSecurityTest"
	"Engine-AntiGinx/App/SiteTests/XContentTypeOptionsTest"
	"Engine-AntiGinx/App/SiteTests/XFrameTest"
	"fmt"
)

// tests is the internal central storage for all registered response tests,
// indexed by their unique string ID. This map provides O(1) lookup performance
// for test retrieval operations.
//
// The map is populated during package initialization via the init() function
// and should not be modified directly outside of the registerTest function.
var tests = make(map[string]SiteTests.Test)

// init automatically registers default security tests when the Registry package is initialized.
// This function runs once before main() and ensures all standard tests are available
// for immediate use throughout the application lifecycle.
//
// Currently registered tests:
//   - HTTPSTest: Verifies HTTPS protocol usage
//   - HSTSTest: Checks HTTP Strict Transport Security headers
//   - ServerHeaderTest: Analyzes server header information
//   - CSPTest: Analyzes Content Security Policy configuration for XSS and injection protection
//   - CookieSecurityTest: Analyzes cookie security attributes and session management
//   - JSObfuscationTest: Detects obfuscated JavaScript code indicating potential security threats
//   - XFrameTest: Analyzes X-Frame-Options and CSP frame-ancestors for clickjacking protection
//   - ReferrerPolicyTest: Analyzes Referrer-Policy header for privacy and information leakage protection
//   - PermissionsPolicyTest: Analyzes Permissions-Policy header for browser feature access control
//   - XContentTypeOptionsTest: Analyzes X-Content-Type-Options header for MIME sniffing protection
//   - SSLCertificateSecurityTest: Analyzes SSL/TLS certificate security and configuration
//   - CrossOriginTest: Analyzes Cross-Origin security headers (COEP, CORP, COOP) for cross-origin attack protection
//   - SitemapSecurityTest: Analyzes sitemap.xml for dangerous path exposure to search engines
//   - PhishingURLTest: Analyzes hostname similarity to popular domains and URL parameters for phishing indicators
//   - BotProtectionTest: Identifies the bot protection, CDN or WAF layer in front of the target
//
// Additional tests can be registered by adding registerTest calls in this function.
func init() {
	registerTest(HTTPSTest.New())
	registerTest(HSTSTest.New())
	registerTest(ServerHeaderTest.New())
	registerTest(CSPTest.New())
	registerTest(CookieSecurityTest.New())
	registerTest(JSObfuscationTest.New())
	registerTest(XFrameTest.New())
	registerTest(ReferrerPolicyTest.New())
	registerTest(PermissionsPolicyTest.New())
	registerTest(XContentTypeOptionsTest.New())
	registerTest(SSLCertificateSecurityTest.New())
	registerTest(CrossOriginTest.New())
	registerTest(SitemapSecurityTest.New())
	registerTest(PhishingURLTest.New())
	registerTest(BotProtectionTest.New())
}

// registerTest adds a new test instance to the internal registry with strict ID uniqueness enforcement.
// This function is intended for internal use during package initialization via the init() function.
//
// The function performs validation to ensure no duplicate test IDs are registered, which could
// cause conflicts in test execution. If a duplicate is detected, it triggers a panic with
// detailed error information.
//
// Parameters:
//   - t: The Test instance to register, of any kind
//
// Panics:
//   - error.Error with code 100: If a test with the same ID already exists in the registry
//
// Example:
//
//	func init() {
//	    registerTest(MyTest.New())
//	}
func registerTest(t SiteTests.Test) {
	if _, exists := tests[t.GetId()]; exists {
		panic(error.Error{
			Code:        100,
			Message:     fmt.Sprintf("Registry error occurred. This could be due to:\n- test with Id %s already exists", t.GetId()),
			Source:      "Registry",
			IsRetryable: false,
		})
	}
	tests[t.GetId()] = t
}

// GetTest retrieves a specific test from the registry by its unique identifier.
// This is the primary method for accessing registered tests and provides thread-safe
// read access to the registry.
//
// The function performs an O(1) map lookup and returns both the test instance and
// a boolean indicating whether the test was found. This pattern allows callers to
// distinguish between a missing test and other error conditions.
//
// Parameters:
//   - testId: The unique string identifier of the test to retrieve (e.g., "https-protocol-check", "hsts-check")
//
// The returned Test may be of any kind; callers schedule it by asking for its GetKind()
// rather than by knowing which concrete type it is.
//
// Returns:
//   - SiteTests.Test: The test instance if found, nil otherwise
//   - bool: true if the test exists in the registry, false if not found
//
// Example:
//
//	test, exists := Registry.GetTest("https-protocol-check")
//	if !exists {
//	    log.Printf("Test not found: https-protocol-check")
//	    return
//	}
//	result := test.Run(scanContext)
func GetTest(testId string) (SiteTests.Test, bool) {
	t, ok := tests[testId]
	return t, ok
}

// GetAllTests returns every registered test, of every kind, in unspecified order.
// The scheduler buckets them by kind, so the order they arrive in does not matter.
//
// Returns:
//   - []SiteTests.Test: All registered tests
func GetAllTests() []SiteTests.Test {
	values := make([]SiteTests.Test, 0, len(tests))
	for _, value := range tests {
		values = append(values, value)
	}
	return values
}

// GetTestsByKind returns every registered test belonging to a single execution phase.
// It lets callers reason about one phase — for example to report which tests were
// skipped because the main request failed — without inspecting concrete types.
//
// Parameters:
//   - kind: The execution phase to filter by
//
// Returns:
//   - []SiteTests.Test: Registered tests of that kind, empty when none match
func GetTestsByKind(kind SiteTests.TestKind) []SiteTests.Test {
	values := make([]SiteTests.Test, 0, len(tests))
	for _, value := range tests {
		if value.GetKind() == kind {
			values = append(values, value)
		}
	}
	return values
}
