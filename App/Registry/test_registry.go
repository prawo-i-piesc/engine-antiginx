// Package Registry stores built-in site tests.
package Registry

import (
	error "Engine-AntiGinx/App/Errors"
	"Engine-AntiGinx/App/SiteTests"
	"Engine-AntiGinx/App/SiteTests/BotProtectionTest"
	"Engine-AntiGinx/App/SiteTests/CSPTest"
	"Engine-AntiGinx/App/SiteTests/CookieSecurityTest"
	"Engine-AntiGinx/App/SiteTests/CrossOriginTest"
	"Engine-AntiGinx/App/SiteTests/DNSReputationTest"
	"Engine-AntiGinx/App/SiteTests/FaviconOriginTest"
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

// tests is populated during package initialization.
var tests = make(map[string]SiteTests.Test)

// init registers the built-in tests.
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
	registerTest(DNSReputationTest.New())
	registerTest(FaviconOriginTest.New())
}

// registerTest panics on duplicate test IDs.
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

// GetTest looks up a test by ID.
func GetTest(testId string) (SiteTests.Test, bool) {
	t, ok := tests[testId]
	return t, ok
}

// GetAllTests returns registered tests in unspecified order.
func GetAllTests() []SiteTests.Test {
	values := make([]SiteTests.Test, 0, len(tests))
	for _, value := range tests {
		values = append(values, value)
	}
	return values
}

// GetTestsByKind filters tests by execution phase.
func GetTestsByKind(kind SiteTests.TestKind) []SiteTests.Test {
	values := make([]SiteTests.Test, 0, len(tests))
	for _, value := range tests {
		if value.GetKind() == kind {
			values = append(values, value)
		}
	}
	return values
}
