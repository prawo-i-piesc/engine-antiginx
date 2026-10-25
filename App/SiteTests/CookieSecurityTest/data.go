package CookieSecurityTest

// Cookie name fragments the analysis recognises.
var (
	// sensitiveCookieNames mark a cookie that carries authority — losing it means losing
	// the account — and that therefore has to be protected by HttpOnly and Secure. They are
	// matched with SiteTests.MatchesNameFragment: "auth" and "jwt" only as a word of their own,
	// so .ASPXAUTH, where "auth" is glued to the name, is listed separately.
	sensitiveCookieNames = []string{"session", "sessid", "auth", "aspxauth", "token", "jwt", "access"}

	// sessionCookieNames mark a cookie as a session identifier for the purpose of
	// reporting how the site manages sessions. "sid" matches connect.sid, not sidebar_state.
	sessionCookieNames = []string{"session", "sessid", "phpsessid", "jsessionid", "aspsessionid", "sid"}
)
