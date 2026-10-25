# Sitemap Security Analysis

Fetches the target's `sitemap.xml` and reports the paths it hands to search engines. A sitemap is a site telling crawlers what to index; when it lists an admin panel, a backup file or a staging area, the site is actively inviting those into search results.

|  |  |
|---|---|
| **Test ID** | `sitemap` |
| **Phase** | Structure — opens its own connection to the target rather than reading the main response |
| **Category** | App-Configuration |

```bash
go run ./App/main.go test --target example.com --tests sitemap
```

## What it checks

- Whether a sitemap exists and is reachable at all.
- Every URL it declares.
- Paths matching known-dangerous fragments — administrative interfaces, backups, configuration, development and staging areas, and internal APIs.
- Paths matching a known sensitive file from the shared [`SensitivePaths`](https://github.com/prawo-i-piesc/engine-antiginx/blob/main/App/SiteTests/SensitivePaths/paths.go) list — the same files the [sensitive-files test](../SensitiveFilesTest/README.md) requests directly from the server.
- The category of each exposure, so a finding says what kind of thing was exposed.

## How it works

1. Request `/sitemap.xml` from the target, over its own connection.
2. Parse the XML and collect every `<loc>` it declares.
3. Match each URL's path — not its hostname, so `test.example.com` is not a `/test` match —
   against the shared `SensitivePaths` files and `SensitivePaths.Locations` fragments,
   using the same `SensitivePaths.Matcher` as the robots.txt test:
   - A fragment must not be followed by a letter, so `/test` matches `/test/`, `/test.php`
     and `/test2` but not `/testimonials`, and `/log` does not match `/login`.
   - When several fragments match, the longest wins, so `/api-docs/` is reported as API
     documentation rather than as an API endpoint, whatever the map order.
   A URL declared twice is reported once.
4. Grade on the count of dangerous paths, not on their categories — one exposed admin panel
   is a finding, thirty exposed paths is a site with no idea what it is publishing.

## What it reports

| Field | Meaning |
|---|---|
| `sitemap_accessible` | Whether a sitemap was found at all |
| `total_urls` | How many URLs it declares |
| `dangerous_paths` | The ones that matched: `url`, the `pattern` that matched and its `category` |
| `total_dangerous` | How many matched |

## How the verdict is reached

| Level | When |
|---|---|
| **None** | No sitemap, or no dangerous path in it |
| **Low** | Up to 2 dangerous paths |
| **Medium** | 3 to 5 |
| **High** | 6 to 10 |
| **Critical** | More than 10 |

## Files

| File | Holds |
|---|---|
| `config.go` | Identity constants, the fetch timeout and 10 MiB size limit, the grading thresholds and the certainty. |
| `core.go` | The test itself: `New()`, merging the shared tables, and the assembled verdict. |
| `modules/sitemapfetch.go` | Retrieval, XML parsing, matching and the judgement. |
| `modules/sitemapfetch_test.go` | Unit tests for matching, metadata, grading and the description, plus a fetch against a local server. |

The test owns no dataset: the fragments it flags live in the shared
[`SensitivePaths`](https://github.com/prawo-i-piesc/engine-antiginx/blob/main/App/SiteTests/SensitivePaths/locations.go) package, which the robots.txt test reads too.

## Notes

An unreachable sitemap is not a finding. Most sites do not publish one, and its absence says nothing about their security.

---

The shared framework and test conventions are described in the [SiteTests overview](../README.md).
