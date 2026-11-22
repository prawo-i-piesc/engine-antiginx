package CookieSecurityTest

// Identity of the test.
const (
	TestId          = "cookie-sec"
	TestName        = "Cookie Security Analysis"
	TestDescription = "Analyzes Set-Cookie headers for security attributes including HttpOnly, Secure, SameSite, expiration times, and session fixation risks"
	TestCategory    = "App-Configuration"
)

// Confidence in the verdict.
const (
	cookieFactCertainty        = 100 // Flags and lifetimes are read straight from Set-Cookie
	cookiePredictableCertainty = 85  // A guessable value is inferred from the value's shape, not by predicting the next one
)

// longLifetimeSeconds is the lifetime beyond which a cookie is reported for outliving any
// reasonable session (one year).
const longLifetimeSeconds = 31536000
