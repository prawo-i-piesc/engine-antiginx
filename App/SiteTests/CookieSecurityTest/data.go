package CookieSecurityTest

// Cookie name fragments the analysis recognises.
var (
	// sensitiveCookieNames mark a cookie that carries authority — losing it means losing
	// the account — and that therefore has to be protected by HttpOnly and Secure. They are
	// matched with SiteTests.MatchesNameFragment: fragments of five characters or more anywhere
	// in the name ("session" covers laravel_session and ci_session), shorter ones only as a word
	// of their own, so "auth" and "sess" match auth_token and koa.sess but not author_pref, and
	// .ASPXAUTH and Drupal's SSESS… cookies are listed separately.
	sensitiveCookieNames = []string{
		"session", "sessid", "sess", "ssess", "auth", "aspxauth", "token", "jwt", "access", "bearer", "saml",
		"remember", "logged_in", "identity", "credential", ".aspnetcore.cookies", "cfid",
	}

	// sessionCookieNames mark a cookie as a session identifier for the purpose of
	// reporting how the site manages sessions. "sid" matches connect.sid, not sidebar_state;
	// "sess" the koa.sess and express:sess cookies of Node session middleware.
	sessionCookieNames = []string{
		"session", "sessid", "sess", "ssess", "phpsessid", "jsessionid", "aspsessionid", "sid",
		"cfid", "cftoken", "cakephp", "symfony", ".aspnetcore.cookies",
	}
)
