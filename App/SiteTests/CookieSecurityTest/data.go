package CookieSecurityTest

// Cookie name fragments the analysis recognises.
var (
	// sensitiveCookieNames mark a cookie that carries authority — losing it means losing
	// the account — and that therefore has to be protected by HttpOnly and Secure.
	sensitiveCookieNames = []string{"session", "sessid", "auth", "token", "jwt", "access"}

	// sessionCookieNames mark a cookie as a session identifier for the purpose of
	// reporting how the site manages sessions.
	sessionCookieNames = []string{"session", "sessid", "phpsessid", "jsessionid", "aspsessionid", "sid"}
)
