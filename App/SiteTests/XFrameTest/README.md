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

`ALLOW-FROM` is graded low rather than as protection because no current browser implements
it — a site relying on it is unprotected while believing it has restricted framing to one
partner.

## What it reports

| Key | Meaning |
|---|---|
| `blocked` / `allowed` | Whether framing is refused, and by whom it is permitted |
| `excellent` … `vulnerable` | The protection band the configuration falls into |

## How the verdict is reached

| Level | When |
|---|---|
| **None** | `frame-ancestors 'none'` or `X-Frame-Options: DENY` |
| **Info** | `frame-ancestors 'self'` or `SAMEORIGIN` |
| **Low** | `ALLOW-FROM`, deprecated and honoured by almost no browser |
| **Medium** | Only `frame-ancestors` with specific domains — partial protection |
| **High** | Neither protection present, or the values are invalid |

## Files

| File | Holds |
|---|---|
| `config.go` | What tunes it: identity constants, thresholds and confidence levels. |
| `core.go` | The test itself: `New()`, the orchestration and the assembled verdict. |

---

The framework this test plugs into, and the conventions every test folder follows, are documented in [`App/SiteTests/Types.go`](../Types.go).
