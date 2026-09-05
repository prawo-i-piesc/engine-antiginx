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

1. Read the twelve headers listed in `data.go` from the response.
2. For each non-empty one, match its value against the signature table
   (`modules/technologydetection.go`) to name the technology, and extract the version from
   whichever format the vendor used — `nginx/1.18.0`, `PHP-7.4.3`, `Apache v2.4.41` and
   bare `IIS 10.0` all parse.
3. For every technology-and-version pair, query the NIST NVD API for known CVEs and collect
   the severity distribution and the highest CVSS score.
4. Grade the disclosure by how much was revealed, then raise it by what the CVE assessment
   says (`modules/cveseverity.go`). A version disclosed with no known vulnerabilities is a
   minor finding; the same disclosure with a high-severity CVE against it is a direct route
   in.

## What it reports

| Field | Meaning |
|---|---|
| `exposed_headers` | Which of the watched headers disclosed something |
| `header_details` | Header name to value, as received |
| `technologies` | Every technology named |
| `technology_stack` | Technology to disclosed version |
| `total_exposures` | How many headers disclosed |

CVE findings are carried in the description rather than the metadata.

## How the verdict is reached

| Level | When |
|---|---|
| **None** | Nothing about the stack is disclosed |
| **Info** | Minimal disclosure, no known vulnerabilities |
| **Low** | A few headers disclose, with only low-severity CVEs |
| **Medium** | Several disclosures, or CVEs of moderate severity |
| **High** | A widely-attacked server is named, or several medium CVEs apply |
| **Critical** | A high-severity CVE applies to a disclosed version, or debug output is exposed |

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

The framework this test plugs into, and the conventions every test folder follows, are documented in [`App/SiteTests/Types.go`](../Types.go).
