# Directory Listing Detection

Probes the target for server-generated directory listings — the `Index of /` pages Apache, nginx, IIS and others produce when a directory has no index file and listing is switched on. A listing hands every visitor the full contents of the directory, including backups, dumps and uploads nobody ever linked to, and it is one of the first things an attacker looks for.

|  |  |
|---|---|
| **Test ID** | `dir-listing` |
| **Phase** | Structure — opens its own connections to the target rather than reading the main response |
| **Category** | App-Configuration |

```bash
go run ./App/main.go test --target example.com --tests dir-listing
```

## What it checks

- The web root.
- The common asset and content directories (`/images/`, `/static/`, `/files/`, `/wp-content/`, …).
- Directories that typically hold sensitive material (`/uploads/`, `/backup/`, `/logs/`,
  `/tmp/`, `/includes/`, `/config/`, …), graded higher.
- Every directory on the way to the scanned page — scanning `example.com/blog/2026/post.html`
  also probes `/blog/2026/` and `/blog/`, where that page's own files live.

## How it works

1. Request each directory over an SSRF-protected connection, at most 5 at a time, each
   with a 10 s budget. Redirects are followed, so `/uploads` → `/uploads/` is handled.
2. Keep only `200` answers with an HTML or text content type, reading at most 256 KiB.
3. Compare the body against the signatures in `data.go`. A signature matches when all of
   its markers appear, case-insensitively; the first match names the server, and a bare
   `<title>Index of /` is the generic fallback. Recognised: Apache, nginx, lighttpd, IIS,
   Tomcat, Jetty, Python `http.server` and Node `serve`. An IIS listing without a parent link (the
   web root) is recognised by its `<dir>` entries followed by their links, so a page that
   only quotes `dir` output in a `<pre>` block is not mistaken for one.
4. For each listing, extract the entries it links to — leaving out the parent directory,
   Apache's column-sorting links and anything outside the listed directory — and keep up
   to 10 of them as evidence.

## How the verdict is reached

| Level | When |
|---|---|
| **None** | No probed directory answers with a listing |
| **Medium** | Listings only in ordinary directories |
| **High** | A listing of the web root or of a sensitive directory |

Each listing is rated on its own, so the number of listed directories never raises the
level; it is reported in the description and the metadata.

Calibrated to OWASP ZAP Directory Browsing (Medium); see the [SiteTests overview](../README.md) for the severity scale.

| Certainty | When |
|---|---|
| 95 | A listing was found; only a page deliberately imitating one would fool the signatures |
| 80 | Nothing was found; only the known directories were probed, not every directory |

## What it reports

| Field | Meaning |
|---|---|
| `probed_paths` | How many directories were requested |
| `reachable_paths` | How many answered `200` with an HTML or text document |
| `listings` | One entry per listing: `path`, `url`, `server`, `sensitive`, `entry_count`, and a sample of `entries` |
| `total_listings` | How many directories are listed |
| `sensitive_listings` | How many of them are sensitive directories |
| `root_listing` | Whether the web root itself is listed |

## Files

| File | Holds |
|---|---|
| `config.go` | Identity constants, probe timeout, size and concurrency limits and certainty levels. |
| `core.go` | `New()`, building the probe list from the datasets and the target's path, and the assembled verdict. |
| `data.go` | The common and sensitive directories, and the listing signatures of each server. |
| `modules/listing.go` | Probing, signature detection, entry extraction, grading and the description. |
| `core_test.go`, `modules/listing_test.go` | Tests on real listing pages of each server, against a local server, and of the grading. |

## Notes

**Probes are visible.** The test makes around 36 requests per target, which shows up in the
target's access logs and may trip rate limiting or a WAF. A blocked probe counts as not
listed, not as an error.

**Not every directory is checked.** A listing is only found where the test looks; a
directory with an unguessable name stays unseen. The `robots-txt` and `sitemap` findings
often name more directories worth checking by hand.

---

The shared framework and test conventions are described in the [SiteTests overview](../README.md).
