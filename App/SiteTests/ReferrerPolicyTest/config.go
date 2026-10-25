package ReferrerPolicyTest

// Identity of the test.
const (
	TestId          = "referrer-policy"
	TestName        = "Referrer-Policy Header Analysis"
	TestDescription = "Checks for Referrer-Policy header presence and configuration to assess referrer information control and privacy protection"
	TestCategory    = "Headers"
)

// missingDescription explains the verdict when the response carries no Referrer-Policy header.
const missingDescription = "Missing Referrer-Policy header - relying on the browser default policy (strict-origin-when-cross-origin in current browsers; older browsers fall back to no-referrer-when-downgrade, which sends the full URL to other sites)"

// Certainty reported when the header is present; an absent header is always reported with
// full certainty.
const Certainty = 100
