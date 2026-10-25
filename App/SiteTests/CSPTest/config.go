package CSPTest

// Identity of the test.
const (
	TestId          = "csp"
	TestName        = "Content Security Policy Analysis"
	TestDescription = "Analyzes Content-Security-Policy header configuration to assess protection against XSS, injection attacks, and resource loading security"
	TestCategory    = "Headers"
)

// missingDescription explains the verdict when the response carries no Content-Security-Policy header.
const missingDescription = "Missing Content-Security-Policy header - site vulnerable to XSS attacks, data injection, and other script-based vulnerabilities. Implement CSP to restrict resource loading and script execution."

// Certainty reported when the header is present; an absent header is always reported with
// full certainty.
const Certainty = 100
