# X-Frame-Options & CSP Frame Protection Analysis

Checks whether the page can be loaded inside someone else's frame. Without that protection an attacker can render the real site invisibly over their own page and collect clicks meant for it — the user interacts with the genuine application and never sees it.

|  |  |
|---|---|
| **Test ID** | `xframe` |
| **Phase** | Response — reads the fetched page; it is the only phase skipped when the main request fails |
| **Category** | Headers |

```bash
go run ./App/main.go test --target example.com --tests xframe
```

## What it checks

- `X-Frame-Options` and its `DENY`, `SAMEORIGIN` and deprecated `ALLOW-FROM` forms.
- The CSP `frame-ancestors` directive, which supersedes the header and is what modern browsers honour.
- The combination of the two, since one may protect where the other does not.
- Malformed values, which browsers ignore, leaving the page unprotected while appearing configured.

## How it works

1. Read `X-Frame-Options` and the `frame-ancestors` directive out of the CSP header.
2. Judge each independently, then take the stronger of the two.
3. `frame-ancestors` wins where the two disagree, because that is what modern browsers do:
   when the directive is present they ignore `X-Frame-Options` entirely.

`ALLOW-FROM` is graded as no protection because no current browser implements it — a site
relying on it is unprotected while believing it has restricted framing to one partner. The
report says so. Broad sources (`*`, `https:`, `http:`) in `frame-ancestors` admit every site
whatever else is listed beside them, so they are graded as no protection too. A
`frame-ancestors` directive with no sources is an empty list and blocks framing like
`'none'`.

## What it reports

| Key | Meaning |
|---|---|
| `has_x_frame_options` / `x_frame_options` | Whether X-Frame-Options was sent, and its value trimmed and uppercased |
| `x_frame_valid` | Whether that value is `DENY`, `SAMEORIGIN` or `ALLOW-FROM` |
| `has_frame_ancestors` / `frame_ancestors` | Whether the CSP names `frame-ancestors`, and its sources as written |
| `protection_level` | `excellent`, `good`, `limited`, `weak` or `vulnerable` — the band the configuration falls into |
| `embedding` | `blocked`, `same-origin`, `limited` or `allowed` — who can frame the page |

## How the verdict is reached

| Level | When |
|---|---|
| **None** | `frame-ancestors 'none'` or `X-Frame-Options: DENY` |
| **Info** | `frame-ancestors 'self'` or `SAMEORIGIN` |
| **Low** | `frame-ancestors` limited to specific domains |
| **Medium** | Neither protection present, invalid values, only `ALLOW-FROM`, or `frame-ancestors` with a broad source (`*`, `https:`, `http:`) |

Calibrated to OWASP ZAP alert 10020 (Anti-clickjacking header, Medium); see the SiteTests overview for the severity scale.

## Files

| File | Holds |
|---|---|
| `config.go` | What tunes it: identity constants, thresholds and confidence levels. |
| `core.go` | The test itself: `New()`, the `FrameAnalysis` it reports as metadata, the analysis and the assembled verdict. |
| `core_test.go` | Unit tests for grading, embedding and the description across both mechanisms. |

---

The shared framework and test conventions are described in the [SiteTests overview](../README.md).
