package CookieSecurityTest

// Cookie name fragments the analysis recognises.
var (
	// sensitiveCookieNames mark a cookie that carries authority — losing it means losing
	// the account — and that therefore has to be protected by HttpOnly and Secure.
	// Fragments are matched case-insensitively anywhere in the name, so "session" already
	// covers laravel_session and ci_session, and "auth" covers .ASPXAUTH and oauth cookies.
	sensitiveCookieNames = []string{
		"session", "sessid", "sess", "auth", "token", "jwt", "access", "bearer", "saml",
		"remember", "logged_in", "identity", "credential", ".aspnetcore.cookies", "cfid",
	}

	// sessionCookieNames mark a cookie as a session identifier for the purpose of
	// reporting how the site manages sessions. "sess" catches Drupal's SESS…/SSESS… names
	// and the koa.sess and express:sess cookies of Node session middleware.
	sessionCookieNames = []string{
		"session", "sessid", "sess", "phpsessid", "jsessionid", "aspsessionid", "sid",
		"cfid", "cftoken", "cakephp", "symfony", ".aspnetcore.cookies",
	}
)
