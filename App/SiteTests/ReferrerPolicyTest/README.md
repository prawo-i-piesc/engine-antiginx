# Referrer-Policy Header Analysis

Reports how much of the current URL the browser hands to the sites a user navigates to. URLs routinely carry session tokens, reset links and account identifiers, and the default policy leaks the full one to every third party a page links to or loads a resource from.

|  |  |
|---|---|
| **Test ID** | `referrer-policy` |
| **Phase** | Response — reads the fetched page; it is the only phase skipped when the main request fails |
| **Category** | Headers |

```bash
go run ./App/main.go test --target example.com --tests referrer-policy
```

## What it checks

- Presence of `Referrer-Policy` and whether its value is a token browsers actually recognise.
- How much the declared policy leaks: the full URL, the origin only, or nothing.
- Whether the policy holds across a downgrade from HTTPS to HTTP.

## How it works

1. Read `Referrer-Policy` and split it on `,` — the header may list several policies as a
   fallback chain for browsers that do not understand the newest token.
2. Discard tokens that are not in the recognised set; a browser that meets one ignores it.
3. The effective policy is the last recognised token, which is how browsers resolve the
   chain.
4. Grade that policy by how much of the URL it lets through, and to whom.

A missing header is graded as the browser default (`no-referrer-when-downgrade` in older
browsers, `strict-origin-when-cross-origin` in current ones), which is why its band sits in
the middle rather than at the bottom.

## What it reports

| Key | Meaning |
|---|---|
| `raw_header` | The header as received |
| `policies` | Every token found |
| `policy_count` | How many were listed |
| `effective_policy` | The token a browser will actually apply |
| `invalid_policies` | Tokens no browser recognises |
| `has_unsafe` | Whether `unsafe-url` appears |

## How the verdict is reached

| Level | When |
|---|---|
| **None** | `strict-origin-when-cross-origin`, `strict-origin` or `no-referrer` |
| **Info** | `origin-when-cross-origin` or `origin` |
| **Low** | `same-origin` |
| **Medium** | `no-referrer-when-downgrade`, which is the browser default and leaks the full URL to other sites |
| **High** | `unsafe-url`, or no header at all |

## Files

| File | Holds |
|---|---|
| `config.go` | What tunes it: identity constants, thresholds and confidence levels. |
| `core.go` | The test itself: `New()`, the orchestration and the assembled verdict. |
| `data.go` | The policy tokens the header is allowed to carry. A header naming anything else is not a weak policy but a broken one: browsers ignore an unrecognised token and fall back to their default. |

---

The framework this test plugs into, and the conventions every test folder follows, are documented in [`App/SiteTests/Types.go`](../Types.go).
