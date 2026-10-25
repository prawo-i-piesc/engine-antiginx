# Cache-Control Analysis (`cache-control`)

A Response test that checks whether a page tied to a user session can end up in a shared cache (proxy, CDN).

## What it checks

A response is **sensitive** when it sets a session-related cookie — one whose name contains, case-insensitively, a fragment from `sessionCookieNames` such as `sess`, `sid`, `auth`, `token`, `jwt` or `remember` — or its body contains `<input type="password">`.

For sensitive responses the test reads `Cache-Control` and `Pragma`:

| Finding | Threat |
|---|---|
| `public` or `s-maxage > 0` without `private`/`no-store` | High |
| only `max-age > 0` without `private`/`no-store` | Medium |
| `Pragma: no-cache` is the only anti-caching header (HTTP/1.0 mechanism) | Medium |
| no `no-store`/`private` at all (heuristic caching possible) | Low |
| `no-store` or `private` present | None |

Responses that are not sensitive are reported as `None`.

## Certainty

100 when the verdict rests on headers and cookies; 85 when it depends on finding a password field by scanning markup.

## Metadata

`CacheAnalysis`: raw `CacheControl` and `Pragma`, parsed directives, `SessionCookies`, `HasPasswordField`, `SharedCacheable`, `PragmaOnlyGuard` and `Issues`.
