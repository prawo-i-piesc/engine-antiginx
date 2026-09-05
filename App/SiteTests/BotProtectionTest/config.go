package BotProtectionTest

// Identity of the test.
const (
	TestId          = "bot-protection"
	TestName        = "Bot Protection Block Assessment"
	TestDescription = "Identifies the bot protection, CDN or WAF layer in front of the target and whether it withholds content behind a challenge"

	// Category is the category worn by every test that reports on a bot protection layer.
	// The scheduler matches on it to tell whether such a test is already part of a scan, so
	// it can leave the verdict to the test instead of synthesizing a competing one.
	Category     = "Bot-Protection"
	TestCategory = Category
)

// Confidence levels reported by this package.
const (
	botProtectionFactCertainty = 100
	botProtectionCertainty     = 45
)

// HttpClient Error Codes that reach this package, named so the two ways a protection layer
// stops a scan can be told apart when the verdict is worded.
const (
	httpBlockedCode            = 102 // Target answered with a challenge instead of its content
	httpProtectionDetectedCode = 300 // Target answered normally, protection detected in front of it
)

// keywordIndicatorPrefix marks a detection that came from generic challenge wording in the
// page rather than from a vendor fingerprint.
const keywordIndicatorPrefix = "Content contains:"
