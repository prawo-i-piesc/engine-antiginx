# Server Technology Disclosure Analysis

Reads what the response headers give away about the software behind them, and asks the NIST NVD database whether the disclosed versions have known vulnerabilities. Disclosure is not a vulnerability on its own; it becomes one when it hands an attacker the exact version to look up.

|  |  |
|---|---|
| **Test ID** | `serv-h-a` |
| **Phase** | Response — reads the fetched page; it is the only phase skipped when the main request fails |
| **Category** | App-Configuration |

```bash
go run ./App/main.go test --target example.com --tests serv-h-a
```

## What it checks

- Twelve headers that commonly name the stack, from `Server` and `X-Powered-By` to `X-Generator` and `X-Drupal-Cache`.
- Which technology each header names, and the version it publishes alongside it.
- Known CVEs for every technology and version pair, retrieved from the NIST NVD API.
- Debug and diagnostic headers, which say more than a version number does.

## How it works

1. Read the headers listed in `data.go` from the response.
2. For each non-empty one, match its value against the signature table
   (`modules/technologydetection.go`) to name the technology, and extract the version from
   whichever format the vendor used — `nginx/1.18.0`, `PHP-7.4.3`, `Apache v2.4.41` and
   bare `IIS 10.0` all parse.
3. For every disclosed release of a technology with a verified CPE product, ask NVD for the
   CVEs it records as affecting that release ([`App/CVE`](../../CVE/README.md)): a lookup by
   CPE, so version ranges decide, not a keyword search. A technology disclosed without a
   release number, or without a CPE product, gets no CVEs — the CVEs filed against nginx
   over the years say nothing about the nginx a site runs — and costs no NVD request.
4. Grade the response by the worse of two things (`modules/cveseverity.go`):
   - **Disclosure** (information exposure, CWE-200): Info for one or two exposing headers,
     Low from three, Medium from five; a disclosed release number is at least Low, since it
     is what an attacker looks up.
   - **Known vulnerabilities**: the CVSS rating of the most severe CVE affecting a disclosed
     release, band for band — CVSS Critical is Critical, High is High, and so on. A CVE NVD
     has not scored yet is Info. The number of CVEs does not raise the level: CVSS rates
     each vulnerability on its own and defines no way to add several up.

## What it reports

| Field | Meaning |
|---|---|
| `exposed_headers` | Which of the watched headers disclosed something, in the order they are read |
| `header_details` | Header name to value, as received |
| `technologies` | Every technology named |
| `technology_stack` | Technology to disclosed version |
| `total_exposures` | How many headers disclosed |
| `vulnerabilities[]` | Per looked-up release: `technology`, `version`, `cpe`, `cve_count`, `total_results`, `unscored`, `max_severity` and `max_score` of the most severe CVE, `risk_level`, the `most_severe` CVEs (up to 5, each with `severity`, `score`, `cvss_version`, `scored_by`), and `lookup_error` when NVD could not be asked |
| `unattributed` | Technologies disclosed without a release number or CPE product, to which no CVE is attributed |

The description names, per release, how many CVEs NVD records, the rating and score of the
most severe and their IDs.

## How the verdict is reached

| Level | When |
|---|---|
| **None** | Nothing about the stack is disclosed |
| **Info** | One or two headers disclose a technology but no release, or the only CVEs against a disclosed release are unscored |
| **Low** | Three or more exposing headers, a disclosed release number, or a CVE rated CVSS Low |
| **Medium** | Five or more exposing headers, or a CVE rated CVSS Medium |
| **High** | A CVE rated CVSS High affects a disclosed release |
| **Critical** | A CVE rated CVSS Critical affects a disclosed release |

Naming a server without its release (`Server: nginx`) is not graded higher for the server's
reputation, and an unreachable NVD leaves the disclosure grade standing while the
description says the CVEs could not be checked.

## Files

| File | Holds |
|---|---|
| `config.go` | What tunes it: identity constants, thresholds and confidence levels. |
| `core.go` | The test itself: `New()`, the orchestration and the assembled verdict. |
| `data.go` | The header list and the signature tables that map a header value to a technology. Teaching the engine a new framework is a matter of adding a row here. |
| `modules/cveseverity.go` | Translates an NVD vulnerability assessment into a threat level. |
| `modules/technologydetection.go` | Matches header values against the signature tables and extracts version numbers from the formats vendors actually use (`nginx/1.18.0`, `PHP-7.4.3`, `Apache v2.4.41`). |

## Notes

This is the only test that calls an external API during a scan. An NVD lookup that fails leaves the disclosure findings intact and only costs the CVE half of the verdict.

---

The shared framework and test conventions are described in the [SiteTests overview](../README.md).
