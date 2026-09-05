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
- The category of each exposure, so a finding says what kind of thing was exposed.

## How it works

1. Request `/sitemap.xml` from the target, over its own connection.
2. Parse the XML and collect every `<loc>` it declares.
3. Match each URL's path against the fragment table in `data.go`, recording which category
   each match falls into.
4. Grade on the count of dangerous paths, not on their categories — one exposed admin panel
   is a finding, thirty exposed paths is a site with no idea what it is publishing.

## What it reports

| Field | Meaning |
|---|---|
| `sitemap_accessible` | Whether a sitemap was found at all |
| `total_urls` | How many URLs it declares |
| `dangerous_paths` | The ones that matched |
| `path_categories` | Each match mapped to its category |
| `total_dangerous` | How many matched |

**Known issue:** these fields are unexported, so `encoding/json` skips them and the
metadata reaches a backend report as `{}`. The finding's description carries the detail.
Fixing it means exporting the fields, which changes what consumers receive — a decision
left open rather than made silently during the restructure.

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
| `config.go` | What tunes it: identity constants, thresholds and confidence levels. |
| `core.go` | The test itself: `New()`, the orchestration and the assembled verdict. |
| `data.go` | The path fragments treated as dangerous, each mapped to the category reported for it. Matching is by substring, so a fragment covers every path containing it. |
| `modules/sitemapfetch.go` | Retrieval, XML parsing and the judgement. It holds the analysis type as well, whose fields are unexported, so the code that reads them has to sit beside it. |

## Notes

An unreachable sitemap is not a finding. Most sites do not publish one, and its absence says nothing about their security.

---

The framework this test plugs into, and the conventions every test folder follows, are documented in [`App/SiteTests/Types.go`](../Types.go).
