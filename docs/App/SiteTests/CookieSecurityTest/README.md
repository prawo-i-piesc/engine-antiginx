# Cookie Security Analysis

Inspects every cookie the response sets and how well each one is protected. A session cookie without `HttpOnly` is readable by any script that gets onto the page, and one without `Secure` is readable by anyone on the network — which turns a minor cross-site scripting bug into a full account takeover.

|  |  |
|---|---|
| **Test ID** | `cookie-sec` |
| **Phase** | Response — reads the fetched page; it is the only phase skipped when the main request fails |
| **Category** | App-Configuration |

```bash
go run ./App/main.go test --target example.com --tests cookie-sec
```

## What it checks

- `HttpOnly`, `Secure` and `SameSite` on each cookie, and the combination of all three.
- Expiration: session cookies versus persistent ones, and lifetimes long enough to outlive the account.
- Cookie names that mark a cookie as carrying authority, held to a stricter standard.
- Values that look predictable, which invite session fixation.
- A per-cookie score and an aggregate for the site.

## How it works

The test runs in two stages, one per file in `modules/`.

**Inspection** (`cookieanalysis.go`) walks every cookie the response sets. For each one it
records the flags it declares, resolves its lifetime, and decides whether it is a session
cookie and whether its name marks it as carrying authority. Because Go's cookie parser
discards some attributes, the raw `Set-Cookie` headers are re-read alongside the parsed
cookies. Individual issues are then aggregated into site-wide ones, so a report can say
"three cookies lack HttpOnly" rather than repeating the same finding three times.

**Scoring** (`scoring.go`) turns those observations into numbers. Each cookie starts at 100
and loses points per missing protection, weighted by what the cookie is: the same missing
`HttpOnly` costs a session cookie far more than a preference cookie. The site's overall
score is the aggregate, and the threat level is derived from it together with the two
booleans that no score should be able to average away — an unprotected session cookie and a
fixation risk. A predictable value is a fixation risk only on a cookie whose name marks it as
a session identifier or a credential: a preference cookie such as `theme=dark` is meant to be
guessable.

## What it reports

| Field | Meaning |
|---|---|
| `totalCookies` | How many cookies the response sets |
| `cookieDetails[]` | Per cookie: `name`, `hasHttpOnly`, `hasSecure`, `sameSite`, `maxAge`, `expiresIn`, `isSessionCookie`, its own issues and score |
| `securityIssues` / `criticalIssues` | Site-wide findings, split by severity |
| `missingHttpOnly` / `missingSecure` / `missingSameSite` | Counts per missing protection |
| `longExpiration` | Cookies that outlive any reasonable session |
| `sessionCookies` | How many were identified as session identifiers |
| `insecureSession` | A session cookie without its protections — not averaged into the score |
| `fixationRisk` | A value that looks predictable |
| `overallSecurityScore` | 0–100 |

## How the verdict is reached

The level is that of the most serious single cookie; several findings do not add up to a
higher one. A cookie whose name marks it as a session identifier or a credential is held to
the stricter standard, because its value is the account.

| Level | When |
|---|---|
| **None** | Every cookie carries `HttpOnly`, `Secure`, `SameSite` and a reasonable lifetime |
| **Info** | Only a lifetime longer than a year, with the flags in place — or no cookie at all |
| **Low** | An ordinary cookie misses `HttpOnly`, `Secure` or `SameSite`; or a session cookie misses only `SameSite` (CSRF, CWE-352 — browsers default to `Lax`) |
| **Medium** | A session cookie misses `HttpOnly` (CWE-1004) or `Secure` (CWE-614) |
| **High** | A session cookie's value looks guessable (session fixation, CWE-330/CWE-384). This is a heuristic, which is why it is not the Critical a confirmed predictable session identifier would be |

Calibrated to OWASP ZAP alerts 10010, 10011 and 10054 (Low) for ordinary cookies and to the
CWE classes named above for session cookies; see the SiteTests overview for the severity scale.

## Files

| File | Holds |
|---|---|
| `config.go` | What tunes it: identity constants, thresholds and confidence levels. |
| `core.go` | The test itself: `New()`, the orchestration and the assembled verdict. |
| `data.go` | The name fragments that mark a cookie as sensitive or as a session identifier, matched with `SiteTests.MatchesNameFragment`: `sessid` covers `PHPSESSID`, while the short `sid` and `auth` count only as a word of their own, so `sidebar_state` and `author_pref` are not sessions. |
| `modules/cookieanalysis.go` | Reads what each cookie declares and collects the issues. |
| `modules/scoring.go` | Turns those issues into a per-cookie and site-wide score. |

---

The shared framework and test conventions are described in the [SiteTests overview](../README.md).
