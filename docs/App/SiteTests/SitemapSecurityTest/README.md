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

1. Request `/sitemap.xml` from the target, over its own connection, reading at most 10 MiB
   of it (`MaxBodyBytes` in `config.go`).
2. Parse the XML and collect every distinct `<loc>` it declares.
3. Match the path of each URL — not its hostname, so `dev.example.com` or `api.example.com`
   is not a finding — against the fragment table in `data.go`, extended at startup with the
   shared `SensitivePaths` list. A fragment must not be followed by a letter, so `/test`
   matches `/test/` and `/test.php` but not `/testimonials`. A URL matching several fragments
   is reported once, under the longest (`/api-docs` is API documentation, not an API endpoint).
   A `<loc>` that is not an absolute URL is matched as written.
4. Grade Low when any dangerous path is declared. How many there are is reported, not graded.

## What it reports

| Field | Meaning |
|---|---|
| `sitemap_accessible` | Whether a sitemap was found at all |
| `total_urls` | How many distinct URLs it declares |
| `dangerous_paths` | The ones that matched, in sitemap order, each with its `url`, the `pattern` it matched and that pattern's `category` |
| `total_dangerous` | How many matched |

The description groups the matches by category, in alphabetical order, with up to three
example URLs per category.

## How the verdict is reached

| Level | When |
|---|---|
| **None** | No sitemap, or no dangerous path in it |
| **Low** | The sitemap declares at least one dangerous path, inviting search engines to index it |

The number of dangerous paths never raises the level: each is the same invitation, and the
count is reported in the description and the metadata.

Calibrated to CWE-200 information disclosure, one band above robots.txt (Info) because the paths are actively submitted for indexing (Low); see the [SiteTests overview](../README.md) for the severity scale.

## Files

| File | Holds |
|---|---|
| `config.go` | What tunes it: identity constants and the retrieval limits. |
| `core.go` | The test itself: `New()`, the orchestration and the assembled verdict. |
| `data.go` | The path fragments treated as dangerous, each mapped to the category reported for it. Matching is by path fragment through the shared `SensitivePaths.Matcher`: the longest fragment a path contains wins, and a fragment must not be followed by a letter. The table is exported as `DangerousPatterns` because the [robots.txt test](../RobotsTxtSecurityTest/README.md) builds on it. |
| `modules/sitemapfetch.go` | Retrieval, XML parsing, matching and the judgement, and the exported analysis type reported as metadata. |

## Notes

An unreachable sitemap is not a finding. Most sites do not publish one, and its absence says nothing about their security.

---

The shared framework and test conventions are described in the [SiteTests overview](../README.md).
