package PhishingURLTest

// Identity of the test.
const (
	TestId          = "phishing-url"
	TestName        = "Phishing URL Analysis"
	TestDescription = "Analyzes the hostname for typo-squatting and homograph patterns and the URL parameters for embedded credentials, sensitive data and redirection abuse"
	TestCategory    = "Phishing"
)

// Structural limits above which a URL is considered abnormally complex.
const (
	maxReasonableQueryLength    = 512 // characters in the raw query string
	maxReasonableParameterCount = 12  // distinct query parameters
	minBrandKeywordLength       = 5   // shortest brand name safe to match in a path
)

// redactedPlaceholder replaces every secret rendered into the reported URL.
const redactedPlaceholder = "[REDACTED]"
