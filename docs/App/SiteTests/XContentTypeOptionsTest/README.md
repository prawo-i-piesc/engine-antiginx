# X-Content-Type-Options Header Analysis

Checks for the one header that stops a browser from second-guessing a response's declared content type. Without it, a file a site serves as plain text or an image can be re-interpreted as script if its bytes happen to look like script — which turns an ordinary upload feature into a way to run code on the site's own origin.

|  |  |
|---|---|
| **Test ID** | `x-content-type-options` |
| **Phase** | Response — reads the fetched page; it is the only phase skipped when the main request fails |
| **Category** | Headers |

```bash
go run ./App/main.go test --target example.com --tests x-content-type-options
```

## What it checks

- Presence of `X-Content-Type-Options`.
- Whether its value is exactly `nosniff`, the only value browsers act on.

## How it works

Read the header, take its first comma-separated value, trim it, lowercase it, compare it to
`nosniff`. That is the whole test — the header has exactly one meaningful value and no
parameters. Only the first value counts because that is what browsers act on (Fetch,
"determine nosniff"), so `nosniff, nosniff` from a duplicating proxy still disables sniffing
while `sniff, nosniff` does not.

A header with a wrong value is graded like an absent one, because the browser ignores it
and sniffs anyway; the description names the value, since it looks configured to someone
auditing the site.

## What it reports

The header as received, so a report can show what was actually sent rather than only that
it was wrong.

## How the verdict is reached

| Level | When |
|---|---|
| **None** | `nosniff` is set (as the first value) |
| **Low** | Header absent, or present with a value browsers ignore — MIME sniffing left enabled |

Calibrated to OWASP ZAP alert 10021 (X-Content-Type-Options header missing, Low); see the SiteTests overview for the severity scale.

## Files

| File | Holds |
|---|---|
| `config.go` | What tunes it: identity constants, thresholds and confidence levels. |
| `core.go` | The test itself: `New()`, the `XContentTypeOptionsAnalysis` it reports as metadata, and the analyze, evaluate and describe stages it plugs into the shared `SiteTests.HeaderTest`. |
| `core_test.go` | Unit tests for grading and descriptions across valid, weak, invalid and missing values. |

---

The shared framework and test conventions are described in the [SiteTests overview](../README.md).
