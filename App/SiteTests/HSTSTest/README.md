# HSTS Header Analysis

Checks whether the site instructs browsers to refuse plaintext connections to it in future. Serving a page over HTTPS protects that one request; HSTS is what protects the next one, including the very first navigation a user types without a scheme.

|  |  |
|---|---|
| **Test ID** | `hsts` |
| **Phase** | Response — reads the fetched page; it is the only phase skipped when the main request fails |
| **Category** | Encryption |

```bash
go run ./App/main.go test --target example.com --tests hsts
```

## What it checks

- Presence and syntactic validity of `Strict-Transport-Security`.
- The `max-age` directive and whether it is long enough to survive between visits.
- `includeSubDomains`, without which a single unprotected subdomain undoes the policy.
- `preload`, which moves the guarantee into the browser itself so even the first visit is protected.

## How it works

1. Read `Strict-Transport-Security` from the response.
2. Split it on `;` into directives and normalise each one.
3. Parse `max-age`. A header whose `max-age` is absent or unparseable is treated as worse
   than a missing header, because browsers discard it entirely while the site's operators
   believe it is in force.
4. Note whether `includeSubDomains` and `preload` are present.
5. Grade `max-age` against two thresholds — one year and six months — and raise the grade
   for each of the two flags.

The one-year threshold is not arbitrary: it is the minimum the browser preload lists
require, so anything shorter cannot be preloaded even if the directive is present.

## What it reports

| Key | Meaning |
|---|---|
| `max_age` | The parsed `max-age` in seconds, `0` when absent or unparseable |
| `include_subdomains` | Whether the directive covers subdomains |
| `preload` | Whether the policy asks to be built into browsers |
| `directives` | Every directive found, as written |

## How the verdict is reached

| Level | When |
|---|---|
| **None** | `max-age` ≥ 1 year, `includeSubDomains` and `preload` |
| **Info** | `max-age` ≥ 1 year with `includeSubDomains` |
| **Low** | `max-age` ≥ 6 months |
| **Medium** | `max-age` shorter than 6 months, or no header at all |
| **High** | Header present but its `max-age` is missing or unparseable, which browsers ignore entirely |

## Files

| File | Holds |
|---|---|
| `config.go` | What tunes it: identity constants, thresholds and confidence levels. |
| `core.go` | The test itself: `New()`, the orchestration and the assembled verdict. |

---

The framework this test plugs into, and the conventions every test folder follows, are documented in [`App/SiteTests/Types.go`](../Types.go).
