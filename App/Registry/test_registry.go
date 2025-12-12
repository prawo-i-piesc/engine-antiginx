// Package Registry provides a thread-safe, centralized registry system for managing
// security test implementations. It acts as a repository for all available ResponseTest
// instances, enabling dynamic test retrieval and execution throughout the application.
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
	"Engine-AntiGinx/App/Tests"
	"fmt"
)

// tests is the internal central storage for all registered response tests,
// indexed by their unique string ID. This map provides O(1) lookup performance
// for test retrieval operations.
//
// The map is populated during package initialization via the init() function
// and should not be modified directly outside of the registerTest function.
var tests = make(map[string]*Tests.ResponseTest)

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
//   - XFrameTest: Analyzes X-Frame-Options and CSP frame-ancestors for clickjacking protection
//
// Additional tests can be registered by adding registerTest calls in this function.
func init() {
	registerTest(Tests.NewHTTPSTest())
	registerTest(Tests.NewHSTSTest())
	registerTest(Tests.NewServerHeaderTest())
	registerTest(Tests.NewCSPTest())
	registerTest(Tests.NewCookieSecurityTest())
	registerTest(Tests.NewXFrameTest())
}

// registerTest adds a new test instance to the internal registry with strict ID uniqueness enforcement.
// This function is intended for internal use during package initialization via the init() function.
//
// The function performs validation to ensure no duplicate test IDs are registered, which could
// cause conflicts in test execution. If a duplicate is detected, it triggers a panic with
// detailed error information.
//
// Parameters:
//   - t: Pointer to the ResponseTest instance to register
//
// Panics:
//   - error.Error with code 100: If a test with the same ID already exists in the registry
//
// Example:
//
//	func init() {
//	    registerTest(Tests.NewCustomTest())
//	}
func registerTest(t *Tests.ResponseTest) {
	if _, exists := tests[t.Id]; exists {
		panic(error.Error{
			Code:        100,
			Message:     fmt.Sprintf("Registry error occurred. This could be due to:\n- test with Id %s already exists", t.Id),
			Source:      "Registry",
			IsRetryable: false,
		})
	}
	tests[t.Id] = t
}

// GetTest retrieves a specific ResponseTest from the registry by its unique identifier.
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
// Returns:
//   - *Tests.ResponseTest: Pointer to the test instance if found, nil otherwise
//   - bool: true if the test exists in the registry, false if not found
//
// Example:
//
//	test, exists := Registry.GetTest("https-protocol-check")
//	if !exists {
//	    log.Printf("Test not found: https-protocol-check")
//	    return
//	}
//	result := test.Run(params)
func GetTest(testId string) (*Tests.ResponseTest, bool) {
	t, ok := tests[testId]
	return t, ok
}
