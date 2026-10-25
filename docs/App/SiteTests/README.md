# SiteTests

Every security test the engine runs, plus the framework they plug into. "Site tests" to
distinguish them from Go unit tests — these examine a target website, not this codebase.

Two Go files sit in this directory and neither is a test: `Types.go` is the framework —
the types every test reports through — and `helpers.go` is the shared toolbox. Everything
else is a test, in its own directory, in its own package — with one exception:
`SensitivePaths/` is a data-only package, not a test. It holds the one list of
known-sensitive files that both `SitemapSecurityTest` and `SensitiveFilesTest` read, so the
definition of "sensitive file" lives in a single place. It declares no `New()` and is not
registered.

## Directory layout

```
SiteTests/
├── Types.go                    the framework
├── helpers.go                  reusable functions for tests
├── README.md                   this file
├── UnitTestKit/                runs tests against prepared data
├── HSTSTest/
│   ├── README.md               what the test is for
│   ├── core.go                 the test itself
│   ├── config.go               what tunes it
│   ├── data.go                 what it knows
│   └── UnitTests/              prepared data and the tests that use it
│       ├── weak_max_age.http
│       ├── …
│       └── hsts_test.go
└── PhishingURLTest/
    ├── README.md
    ├── core.go
    ├── config.go
    ├── data.go
    └── modules/                stages, for a test that has several
        ├── domainimpersonation.go
        └── urlparameters.go
```

The split is by **rate of change**, not by size. A test's logic is rewritten rarely, its
thresholds are adjusted occasionally, and its datasets — the brands it knows, the paths it
considers dangerous, the headers it recognises — change constantly, because the things
being detected change. Keeping the three apart means the frequent edit is a small edit to
an obvious file, made without reading the algorithm around it.

| File | Holds | Rule |
|---|---|---|
| `README.md` | What the test is for, why its findings matter, the threat scale it reports, what it returns | The documentation lives here, not in godoc. Code comments are kept to one line. |
| `core.go` | `New()`, the orchestration, the assembled verdict | The only file you must read to know what a test does |
| `config.go` | Identity constants, thresholds, confidence levels, timeouts | Numbers only — nothing that decides |
| `data.go` | Reference datasets | Data only — nothing that decides |
| `modules/` | Stage implementations, as a package of its own | Only for a test with several stages |

**`modules/` owns no data.** `core.go` injects the datasets from `data.go` and the limits
from `config.go`, so the dependency runs one way (`core → modules`) and a stage can be
exercised on its own. Go would reject the reverse as an import cycle.

**`modules/` is by convention private to its test.** Go cannot enforce that for a directory
named `modules` — renaming it to `internal` would make the compiler enforce it, at the cost
of an extra directory level.

## Shared helpers

`helpers.go` holds what more than one test needs, so a second test never re-solves a
problem the first one already solved. A function earns a place here when it is used by at
least two tests, or when it is general enough that the next test would otherwise write its
own — the point is to stop five slightly different header parsers from existing.

| Function | Does |
|---|---|
| `NormalizeHeaderValue(value)` | Trims and lowercases a header value for comparison |
| `SplitHeaderList(header, sep)` | Splits a header, trimming parts and dropping empties |
| `ParseDirectives(header)` | Parses a `;`-separated directive header into name → values. First occurrence of a repeat wins, as browsers resolve it |
| `DirectiveValue(header, name)` | One directive's values, and whether it was present — a directive with no values is not an absent one |
| `ContainsAnyFold(haystack, needles)` | Whether any needle appears, ignoring case |
| `FindAllFold(haystack, needles)` | Which needles appear, ignoring case, in the order given |
| `ContainsStandaloneToken(haystack, token)` | Whether a token appears delimited by non-alphanumerics, so `google` does not match inside `googleapis` |
| `MatchesNameFragment(name, fragments)` | Whether a name (a cookie's) contains a fragment, ignoring case. Fragments of five characters or more match anywhere (`session` in `laravel_session`); shorter ones only as a word of their own (`sid` in `connect.sid`, not in `sidebar_state`) |
| `UniqueStrings(values)` | Deduplicates, preserving first-seen order |
| `HighestThreatLevel(levels...)` | The most severe level given |
| `EscalateThreatLevel(level)` | Raises a level by one, capped at `Critical` — how a test says several findings together mean more than the worst alone |
| `FormatDuration(seconds)` | Renders seconds as the largest whole unit that fits |
| `RegistrableDomain(host)` | Reduces a hostname to the domain somebody registered with a registry — what RDAP knows about |
| `SiteDomain(host)` | Reduces a hostname to the site it belongs to: the registrable domain, except on hosting platforms that give each customer a subdomain (`github.io`, `vercel.app`…), where `alice.github.io` and `bob.github.io` are different sites |

Two things deliberately stay out. `CookieSecurityTest` keeps its own duration formatter
because its wording differs (`1 year(s) 30 day(s)` against `1 year`), and unifying them
would change what reports say. Anything that encodes one test's judgement — its thresholds,
its datasets — belongs in that test's `config.go` or `data.go`, never here.

## Uniform names

Every test package declares the same symbols. This is what lets the registry, and any
future automation that discovers tests by scanning this directory, work without knowing
which test it is looking at.

| Symbol | In | Is |
|---|---|---|
| `New()` | `core.go` | The constructor, returning one of the three test types |
| `TestId` | `config.go` | The `--tests` identifier |
| `TestName` | `config.go` | The display name carried in every result |
| `TestDescription` | `config.go` | One line, shown in help |
| `TestCategory` | `config.go` | `Headers`, `Encryption`, `App-Configuration`, `Phishing`, `Bot-Protection` |

## Execution phases

A test declares what it needs, and that decides when the scheduler runs it. You never
select a phase — it follows from the test.

| Kind | Needs | Behaviour |
|---|---|---|
| `PreResponseTest` | The target URL only | Runs immediately, in parallel with the page fetch. Still reports when the target is unreachable or blocked. |
| `ResponseTest` | The fetched page | The only phase skipped when the main request fails |
| `StructureTest` | The target's configuration | Opens its own connections — TLS handshake, sitemap fetch |

The split is why a blocked target still produces a report: only the Response tests are
skipped, and the report names them.

## Threat levels

| | Level | Means | CVSS 3.x/4.0 rating |
|---|---|---|---|
| 0 | `None` | No issue found; the configuration meets what is expected | None (0.0) |
| 1 | `Info` | Worth knowing, no security impact | — (no counterpart) |
| 2 | `Low` | Minor issue, low exploitability | Low (0.1–3.9) |
| 3 | `Medium` | Needs attention | Medium (4.0–6.9) |
| 4 | `High` | Serious, with real impact | High (7.0–8.9) |
| 5 | `Critical` | Severe, remediate immediately | Critical (9.0–10.0) |

Levels serialise to their names in JSON, not to numbers.

The five levels other than `Info` share their names and order with the CVSS qualitative
severity ratings, and where a level comes from a CVE it is that CVE's CVSS rating band for
band — see [`App/CVE`](../CVE/README.md) for how a CVE is rated and why several are never
added up. `Info` has no CVSS counterpart: it marks a finding with no security impact of its
own, or a CVE that is known but not yet scored. A level a test assigns to a configuration
finding (a missing header, a weak cookie) is that test's judgement, documented in its README;
it is not a CVSS score, since CVSS rates vulnerabilities, not configurations.

### How tests choose a level

Tests answer one of two questions, and grade accordingly.

**Weaknesses of the site** — headers, cookies, caching, TLS, exposed files and listings,
robots.txt and sitemap, disclosed software. A finding is graded by what the weakness lets an
attacker do, calibrated to the risk levels of OWASP ZAP's alerts (Nessus for TLS) and to the
typical CVSS 3.1 band of the vulnerability class it opens:

| Kind of finding | Level | Example |
|---|---|---|
| Nothing to report, or a hint with no security impact | None / Info | `Referrer-Policy` absent (browsers default to a safe policy) |
| Missing defence in depth, nothing directly exploitable | Low | No `X-Content-Type-Options`, no HSTS, an ordinary cookie without `HttpOnly` |
| Missing protection against a directly exploitable attack class | Medium | No CSP (XSS), no anti-framing (clickjacking), plain HTTP, an untrusted certificate, directory browsing |
| Direct exposure of confidential data | High | A readable `.env`, `.git` or database dump; a guessable session identifier |
| A CVE rated Critical by CVSS affecting a disclosed release | Critical | Only the server-header test reaches it |

Like CVSS, which rates each vulnerability on its own, these tests report their most serious
single finding: ten findings of one level are that level. Counts go to the metadata.

**Evidence that the target is malicious** — phishing URL, URLhaus, DNS reputation, favicon
origin, JavaScript obfuscation, bot protection. These do not rate a weakness of the site but
how strongly the evidence says the target is dangerous to visit, so independent indicators
pointing the same way may raise the level together. A detected bot-protection layer is
reported for information only.

Each test's README names the alerts or classes its levels are calibrated to.

## What a test returns

```go
type TestResult struct {
    Name        string      // the test's display name
    Certainty   int         // 0-100, confidence in this finding
    ThreatLevel ThreatLevel // the classification above
    Metadata    any         // test-specific detail; each test's README documents its shape
    Description string      // the finding, in the operator's terms
}
```

`Certainty` is about confidence in the finding, not about severity. A deterministic check
reports 100 whatever it found; a heuristic reports lower, and a test whose sources were
unreachable reports lower still.

## Unit tests

Every test keeps prepared data specific to it in its own `UnitTests/` directory, next to Go
tests that run it through its public `New()` — the same `Run` the scheduler calls during a
scan — and check the verdict, the description and the metadata. They need no network: sites
are served locally and external services are replaced by stand-ins.

| Kind of test | Prepared data | Run with |
|---|---|---|
| `Response` | `.http` files: a raw HTTP response as it travels on the wire — status line, headers, blank line, body. An optional `X-Fixture-URL:` pseudo-header names the address it was served from. | `UnitTestKit.RunResponse(t, X.New(), "weak_max_age.http")` |
| `Structure` | A directory per scenario laid out as a website (`sites/exposed_env/.env`, `sites/apache_uploads/uploads/index.html`) | `UnitTestKit.ServeSite(t, dir, options...)`, then `UnitTestKit.RunTarget(t, X.New(), server.URL)` |
| `PreResponse` | Target URLs, and prepared answers of the external service the test consults (RDAP, URLhaus) | `UnitTestKit.RunTarget(t, X.New(), address)` against a local stand-in named through the test's environment variable |

`UnitTestKit` also provides `Expect(t, result, level, fragments...)`, `Metadata(t, result)` —
the metadata as the JSON a report carries — and `ServeNVD`, a stand-in for the NVD API used by
the server-header and CVE tests. `ServeSite` lifts the SSRF protection for the duration of the
test only.

A fixture is named after what it represents (`missing_header.http`, `soft_not_found/`) and
carries a line of body text saying so. Fixtures that look like what a scanner hunts for are obviously fake
(`DB_PASSWORD=fixture-not-a-real-password`, `CVE-2099-…`). Where the repository's `.gitignore`
would drop a fixture (`*.pem`, `.env`), a `.gitignore` next to it re-includes it; a `.git`
directory cannot be committed at all, so that site stores it as `dot-git/` and the test copies
it under its real name before serving. Tests assert what the test *should* report: a
behaviour that is a bug is left out and reported, never written down as expected.

```bash
go test ./App/...
```

## Adding a test

1. Create `SiteTests/<Name>Test/`.
2. Write `README.md`, `core.go`, `config.go` and — if it has data — `data.go`, and prepared
   data with its tests in `UnitTests/`.
3. Register the package's `New()` in [`App/Registry`](../Registry/README.md).
4. Add the identifier to the `--tests` whitelist in [`App/parser`](../parser/README.md).
5. Add the test to the table in [CLI guide](../../QuickStart/CLI.md) and
   to the nav in [`mkdocs.yml`](https://github.com/prawo-i-piesc/engine-antiginx/blob/main/mkdocs.yml) so the new page appears in the navigation.
   The strict build fails for broken navigation entries and invalid documentation links.
