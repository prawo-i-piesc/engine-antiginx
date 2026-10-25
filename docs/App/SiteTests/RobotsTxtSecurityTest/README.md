# Robots.txt Security Analysis

Fetches the target's `robots.txt` and reports the sensitive paths its rules name. The file is public and is often the first thing an attacker reads: a `Disallow: /admin/` does not protect anything, it only asks polite crawlers to stay away while telling everyone else where the admin panel is. An `Allow` rule for such a path is worse still, because it explicitly invites crawlers in.

|  |  |
|---|---|
| **Test ID** | `robots-txt` |
| **Phase** | Structure — opens its own connection to the target rather than reading the main response |
| **Category** | App-Configuration |

```bash
go run ./App/main.go test --target example.com --tests robots-txt
```

## What it checks

- Whether a `robots.txt` exists and is reachable at all.
- Every `Allow` and `Disallow` rule it declares, across all `User-agent` groups.
- Rule paths matching known-dangerous fragments — the whole
  [sitemap](../SitemapSecurityTest/README.md) table, the shared
  [`SensitivePaths`](https://github.com/prawo-i-piesc/engine-antiginx/blob/main/App/SiteTests/SensitivePaths/paths.go)
  file list (the same files the [sensitive-files test](../SensitiveFilesTest/README.md)
  requests from the server), and what robots files typically name on top of those: login
  pages, installers, server internals, credentials, uploads, and file-type wildcards such
  as `/*.sql$`.
- Whether a matching `Allow` rule actively exposes a sensitive path, or only carves an
  exception out of a disallowed one.

## How it works

1. Request `/robots.txt` from the target, over its own SSRF-protected connection, reading
   at most 500 KiB — where Google stops parsing as well.
2. Parse it line by line: comments are dropped, directive names are case-insensitive, empty
   `Disallow:` lines (which disallow nothing) and repeated rules are skipped. Other
   directives — `User-agent`, `Sitemap`, `Crawl-delay` — are ignored.
3. Match each rule's path against the shared `SensitivePaths` list and
   `SitemapSecurityTest.DangerousPatterns`, merged with the test's own `data.go`, using
   `SensitivePaths.Matcher` — the same matching the sitemap test uses:
   - A fragment must not be followed by a letter, so `/test` matches `/test/`, `/test.php`
     and `/test2` but not `/testimonials`, and `/log` does not match `/login`.
   - When several fragments match, the longest wins, so `/api-docs/` is reported as API
     documentation rather than as an API endpoint, whatever the map order.
4. Mark each matching `Allow` as exposed, unless it lies under a disallowed sensitive path —
   WordPress's default `Disallow: /wp-admin/` + `Allow: /wp-admin/admin-ajax.php` only
   narrows the Disallow, while `Disallow: /` + `Allow: /admin/` opens the admin area.
5. Grade on the kind of finding: Info when rules only name sensitive paths, Low when an `Allow` exposes one.

## What it reports

| Field | Meaning |
|---|---|
| `robots_accessible` | Whether a robots.txt was found at all |
| `total_rules` | How many distinct Allow/Disallow rules it declares |
| `dangerous_rules` | The ones that matched: `directive`, `path`, the `pattern` that matched, its `category`, and `exposed` |
| `total_dangerous` | How many matched |
| `total_exposed` | How many of them are exposing Allow rules |

Unlike the sitemap test, the fields are exported, so the metadata reaches a backend report
in full.

## How the verdict is reached

| Level | When |
|---|---|
| **None** | No robots.txt, or no sensitive path in it |
| **Info** | `Disallow` rules name sensitive paths. The file is public by design, so this only aids reconnaissance (CWE-200) |
| **Low** | An `Allow` rule that is not a carve-out of a disallowed sensitive path invites crawlers into a sensitive area |

The number of sensitive rules never raises the level: each rule is the same disclosure, and
the count is reported in the description and the metadata.

Calibrated to CWE-200 information disclosure: robots.txt is public by design and only helps
reconnaissance, so it is graded below every weakness that can be exploited directly. OWASP ZAP
has no alert for robots.txt contents to compare with. See the
[SiteTests overview](../README.md) for the severity scale.

## Files

| File | Holds |
|---|---|
| `config.go` | Identity constants, the fetch timeout and size limit and the certainty. |
| `core.go` | The test itself: `New()`, merging the sitemap table with this test's own, and the assembled verdict. |
| `data.go` | The fragments added on top of the sitemap table, each mapped to its category. An entry here overrides a sitemap entry with the same fragment. |
| `modules/robotsfetch.go` | Retrieval, parsing, matching and the judgement. |
| `modules/robotsfetch_test.go` | Unit tests for parsing, matching, carve-outs and grading, plus fetches against a local server. |

## Notes

An unreachable robots.txt is not a finding — there are no rules to reveal anything.

Where to add a path: a sensitive **file** goes in the shared `SensitivePaths` list, which
this test, the sitemap test and the sensitive-files test all read. A dangerous **location**
fragment shared with the sitemap test goes in the sitemap's `data.go`; one only robots.txt
should flag goes in this test's `data.go`.

---

The shared framework and test conventions are described in the [SiteTests overview](../README.md).
