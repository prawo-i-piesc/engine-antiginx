package CredentialFormTest

// Identity of the test.
const (
	TestId          = "credential-form"
	TestName        = "Credential Form Analysis"
	TestDescription = "Finds forms with password, card or one-time code fields and checks where they submit, and inline scripts that send form values to data-collection services"
	TestCategory    = "Phishing"
)

// Confidence in the verdict.
const (
	credentialFactCertainty    = 100 // Where a form submits is read straight from the page
	credentialForeignCertainty = 70  // Single sign-on and payment gateways legitimately receive forms on another domain
	credentialScriptCertainty  = 90  // A script sending field values to a collector is read from the page, but not executed
	credentialScriptUncertain  = 80  // The script sends to a collector, but no read of field values was recognised
	credentialUnreadable       = 50  // The page or its address could not be read
)

// maxScannedBody caps how much of the page is searched. Phishing pages often inline large
// images and scripts, so the cap is generous.
const maxScannedBody = 2 * 1024 * 1024
