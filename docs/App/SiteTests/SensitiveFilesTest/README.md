# Sensitive File Exposure

A small, targeted dirbuster. It requests a curated list of files that should never be reachable on a public server — environment files, backup copies of configuration, `.git` and `.svn` directories, database dumps, archive backups, server-information endpoints, logs and development artefacts — and reports the ones the server actually serves.

The list is the shared [`SensitivePaths`](https://github.com/prawo-i-piesc/engine-antiginx/blob/main/App/SiteTests/SensitivePaths/paths.go) dataset, the same definition of "sensitive file" the [sitemap test](../SitemapSecurityTest/README.md) flags when a sitemap declares one. Adding a path there teaches both tests at once.

|  |  |
|---|---|
| **Test ID** | `sensitive-files` |
| **Phase** | Structure — opens its own connections to the target rather than reading the main response |
| **Category** | App-Configuration |

```bash
go run ./App/main.go test --target example.com --tests sensitive-files
```

## What it checks

Each file in the shared list, requested directly. The categories are secrets &
configuration, credentials, version control, database dumps, archive backups, server
information, logs and development artefacts.

## How it works

1. **Baseline first.** Request two or three random, unguessable paths. This reveals what the
   server does with a file that certainly does not exist — a clean server answers `404`, but
   many answer `200` with the homepage (a *soft 404*) or `403` for everything.
2. **Sweep.** Request every candidate over an SSRF-protected connection, at most 8 at a time,
   each with a 10 s budget and reading at most 64 KiB.
3. **Classify against the baseline**, so a server that answers for everything is not mistaken
   for one leaking files:
   - `200` → **readable**, unless the server soft-404s and the body is within 5% of the
     soft-404 page's length, in which case it is treated as a miss.
   - `401` / `403` → **present but access-controlled**, but only when that status is not what
     the server returns for missing paths anyway. A reachable `.git/config` blocked by a
     `403` still proves the repository is there.
   - anything else → not found.

## How the verdict is reached

The severity of a readable file follows its category:

| Category | Severity |
|---|---|
| Credentials, Version Control, Secrets & Configuration, Database Dump, Backup | High |
| Server Information, Log File | Medium |
| Development Artifact | Low |

The result is the most severe readable file found. Each file is rated on its own, so the
number of readable files never raises the level; it is reported in the description and the
metadata. A file that only *exists* behind access control is a Low note and does not drive
the verdict. Nothing readable, nothing found → **None**.

Calibrated to OWASP ZAP Source Code Disclosure - Git (High) and the CVSS 3.1 band of
confidential-data exposure (C:H, about 7.5). OWASP ZAP rates a leaked `.env` (40034) and
`.htaccess` (40032) Medium; this test rates readable secrets and configuration High, because
the file is served whole and such files typically hold working credentials — the
confidentiality impact CVSS rates High. See the [SiteTests overview](../README.md) for the
severity scale.

| Certainty | When |
|---|---|
| 95 | A file was served as itself, distinct from the server's missing-file answer |
| 80 | Nothing was found — only the known list was tried, not every possible file |

## What it reports

| Field | Meaning |
|---|---|
| `probed` | How many files were requested |
| `soft_not_found` | Whether the server answers `200` for missing paths |
| `baseline_status` | The statuses the random baseline paths returned |
| `exposures` | One entry per hit: `path`, `url`, `category`, `status`, `protected`, `size`, `content_type` |
| `readable_count` | Hits whose content was served |
| `protected_count` | Hits that exist but are access-controlled |

## Files

| File | Holds |
|---|---|
| `config.go` | Identity constants, probe timeout, size and concurrency limits, the soft-404 window and certainty levels. |
| `core.go` | `New()`, converting the shared list into candidates and wiring the severity map and limits into the sweep. |
| `data.go` | The category-to-severity map — this test's judgement, kept out of the shared list. |
| `modules/prober.go` | Baselining, the concurrent sweep, classification, grading and the description. |
| `core_test.go`, `modules/prober_test.go` | Tests of the candidate list and the grading, and of the sweep against honest-404, soft-404 and forbid-everything servers. |

## Notes

**The list is a starter set, not a wordlist.** Every entry is a file whose mere presence is
a finding. It is deliberately small and high-signal; it is not a full brute-force dictionary,
and it will not find a secret at an unusual path.

**Probes are visible.** The test makes around 85 requests per target, which shows up in
access logs and may trip rate limiting or a WAF. A blocked request counts as not found.

**The scanned URL is never reached.** The files are requested relative to the site root, not
the target's path, so the test behaves the same whatever page was given.

---

The shared framework and test conventions are described in the [SiteTests overview](../README.md).
