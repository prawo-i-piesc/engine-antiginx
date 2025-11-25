// Package Tests provides security testing functionality for Engine-AntiGinx.
//
// # HTTPSTest Module
//
// This module implements HTTPS protocol verification to ensure secure communication
// channels. It validates whether websites enforce encrypted HTTPS connections
// instead of insecure HTTP, which is critical for protecting data in transit.
//
// Security Importance:
//
// HTTPS (HTTP Secure) uses TLS/SSL encryption to:
//   - Encrypt data transmission preventing eavesdropping
//   - Authenticate the server preventing man-in-the-middle attacks
//   - Ensure data integrity preventing tampering
//   - Meet compliance requirements (PCI DSS, GDPR, HIPAA)
//
// HTTP vs HTTPS:
//
//	HTTP:  No encryption, data sent in plaintext → High threat
//	HTTPS: TLS/SSL encryption, secure transmission → No threat
//
// Threat Assessment:
//
//   - ThreatLevel.None: Website uses HTTPS with proper encryption
//   - ThreatLevel.High: Website uses HTTP exposing data to interception
//
// This test is typically the first security check performed as it validates
// the fundamental security posture of a web application.
//
// Integration:
//
// This test is registered in the test registry and executed by the job runner
// during security scanning operations.
package Tests

// NewHTTPSTest creates a new security test that verifies HTTPS protocol usage.
// This test checks whether the target website enforces encrypted HTTPS connections
// or allows insecure HTTP communication.
//
// Test Behavior:
//
// The test examines the URL scheme of the HTTP response to determine the protocol:
//   - If scheme is "https": Returns ThreatLevel.None (secure)
//   - If scheme is "http": Returns ThreatLevel.High (insecure)
//
// Security Implications:
//
// HTTP connections transmit data in plaintext, making them vulnerable to:
//   - Packet sniffing and eavesdropping
//   - Man-in-the-middle (MITM) attacks
//   - Data tampering and injection
//   - Session hijacking
//   - Credential theft
//
// HTTPS provides:
//   - End-to-end encryption (TLS/SSL)
//   - Server authentication via certificates
//   - Data integrity verification
//   - Protection against passive and active attacks
//
// Certainty:
//
// This test always returns 100% certainty as protocol detection is deterministic
// based on the URL scheme in the HTTP response object.
//
// Returns:
//   - *ResponseTest: Configured test instance ready for execution
//
// Example:
//
//	// Create the HTTPS test
//	httpsTest := NewHTTPSTest()
//
//	// Execute against target (via Runner)
//	params := ResponseTestParams{
//	    Response: httpResponse,
//	    Url:      "https://example.com",
//	}
//	result := httpsTest.Run(params)
//
//	// Secure site (HTTPS)
//	// result.ThreatLevel = None
//	// result.Description = "Connection is secured with HTTPS protocol..."
//
//	// Insecure site (HTTP)
//	// result.ThreatLevel = High
//	// result.Description = "Connection uses insecure HTTP protocol..."
//
// Related Tests:
//   - HSTSTest: Validates HTTP Strict Transport Security headers
//   - ServerHeaderTest: Analyzes server headers for security issues
func NewHTTPSTest() *ResponseTest {
	return &ResponseTest{
		Id:          "https",
		Name:        "HTTPS Protocol Verification",
		Description: "Verifies if the website communication is secured with HTTPS protocol",
		RunTest: func(params ResponseTestParams) TestResult {

			if params.Response.Request.URL.Scheme == "https" {
				return TestResult{
					Name:        "HTTPS Protocol Verification",
					Certainty:   100,
					ThreatLevel: None,
					Metadata:    nil,
					Description: "Connection is secured with HTTPS protocol - data transmission is encrypted",
				}
			}

			return TestResult{
				Name:        "HTTPS Protocol Verification",
				Certainty:   100,
				ThreatLevel: High,
				Metadata:    nil,
				Description: "Connection uses insecure HTTP protocol - data is transmitted in plaintext and vulnerable to interception",
			}
		},
	}
}
