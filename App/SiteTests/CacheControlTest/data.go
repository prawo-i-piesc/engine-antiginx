package CacheControlTest

import "regexp"

// sessionCookieNames mark a cookie as one that ties the response to a user session. They are
// matched with SiteTests.MatchesNameFragment: fragments of five characters or more anywhere in
// the name ("session" covers every *_session name, "ssess" Drupal's SSESS… cookies), shorter
// ones only as a word of their own — "sid" and "auth" match connect.sid and auth_token, not
// sidebar_state or author_pref, so .ASPXAUTH is listed separately.
var sessionCookieNames = []string{
	"session", "sessid", "sess", "ssess", "phpsessid", "jsessionid", "aspsessionid", "sid", "cfid", "cftoken",
	"cakephp", "symfony", ".aspnetcore.cookies", "auth", "aspxauth", "token", "jwt", "bearer", "saml",
	"remember", "logged_in", "identity", "credential",
}

// passwordInput matches an input element whose type is password, in any attribute order and
// quoting style.
var passwordInput = regexp.MustCompile(`(?is)<input\b[^>]*\btype\s*=\s*["']?\s*password\b`)

// CacheAnalysis is the metadata reported by the test.
type CacheAnalysis struct {
	CacheControl     string   `json:"CacheControl"`     // Cache-Control header values as sent
	Pragma           string   `json:"Pragma"`           // Pragma header value as sent
	SessionCookies   []string `json:"SessionCookies"`   // Names of session-related cookies set
	HasPasswordField bool     `json:"HasPasswordField"` // Page contains a password input
	Sensitive        bool     `json:"Sensitive"`        // Response is tied to a session or credentials
	Public           bool     `json:"Public"`           // Cache-Control: public
	MaxAge           int      `json:"MaxAge"`           // max-age in seconds, -1 when absent
	SharedMaxAge     int      `json:"SharedMaxAge"`     // s-maxage in seconds, -1 when absent
	Private          bool     `json:"Private"`          // Cache-Control: private
	NoStore          bool     `json:"NoStore"`          // Cache-Control: no-store
	NoCache          bool     `json:"NoCache"`          // Cache-Control: no-cache
	SharedCacheable  bool     `json:"SharedCacheable"`  // Shared cache may store the response
	PragmaOnlyGuard  bool     `json:"PragmaOnlyGuard"`  // Pragma: no-cache is the only anti-caching header
	Issues           []string `json:"Issues"`           // Human-readable findings
}
