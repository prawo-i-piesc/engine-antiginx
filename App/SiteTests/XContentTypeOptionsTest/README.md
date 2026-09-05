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

Read the header, trim it, lowercase it, compare it to `nosniff`. That is the whole test —
the header has exactly one meaningful value and no parameters.

The middle band exists because a header with a wrong value is worse than an absent one in
one specific way: it looks configured. Someone auditing the site sees the header present
and moves on, while the browser ignores it and sniffs anyway.

## What it reports

The header as received, so a report can show what was actually sent rather than only that
it was wrong.

## How the verdict is reached

| Level | When |
|---|---|
| **None** | `nosniff` is set |
| **Medium** | Header present with a value browsers ignore |
| **High** | Header absent, MIME sniffing left enabled |

## Files

| File | Holds |
|---|---|
| `config.go` | What tunes it: identity constants, thresholds and confidence levels. |
| `core.go` | The test itself: `New()`, the orchestration and the assembled verdict. |

---

The framework this test plugs into, and the conventions every test folder follows, are documented in [`App/SiteTests/Types.go`](../Types.go).
