package CSPTest

// Identity of the test.
const (
	TestId          = "csp"
	TestName        = "Content Security Policy Analysis"
	TestDescription = "Analyzes Content-Security-Policy header configuration to assess protection against XSS, injection attacks, and resource loading security"
	TestCategory    = "Headers"
)

// criticalStrengthCap is the highest strength a policy with a critical vulnerability can
// score, below the weak band.
const criticalStrengthCap = 19
