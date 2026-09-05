# Content Security Policy Analysis

Judges the policy that decides what a page is allowed to load and execute. CSP is the last line of defence against injected script: when everything else has failed and an attacker's markup is already on the page, a strict policy is what stops it from running.

|  |  |
|---|---|
| **Test ID** | `csp` |
| **Phase** | Response — reads the fetched page; it is the only phase skipped when the main request fails |
| **Category** | Headers |

```bash
go run ./App/main.go test --target example.com --tests csp
```

## What it checks

- Presence of `Content-Security-Policy` and the directives it declares.
- Values that hand back the capability the directive was meant to remove — `'unsafe-inline'`, `'unsafe-eval'` and the `*` wildcard.
- Whether unsafe values sit in directives that actually matter for injection, rather than anywhere in the policy.
- Nonces and hashes, which make an inline script explicitly allowed rather than blanket-permitted.
- Directives a policy is expected to set and does not.

## How it works

1. Split the header on `;` into directives, and each directive into its name and values.
2. Check every directive for unsafe values, weighting a hit in one of the critical
   directives — the ones that govern script — above a hit anywhere else.
3. Look for nonces and hashes. An inline script allowed by a nonce is a deliberate
   exception; one allowed by `'unsafe-inline'` is a blanket permission, and the two are
   graded very differently even though both permit inline script.
4. List the recommended directives the policy does not set.
5. Score policy strength from coverage and strictness, and map the score to a protection
   level.

`frame-ancestors` is checked here as well as in the `xframe` test, because it belongs to
both stories: it is part of the policy's completeness and it is the clickjacking defence.

## What it reports

The parsed policy, the directives it declares, the unsafe values found in each, the
recommended directives it is missing, a policy strength score and the protection level
that score maps to (`excellent`, `good`, `acceptable`, `weak`, `poor`).

## How the verdict is reached

| Level | When |
|---|---|
| **None** | Comprehensive policy, strict directives, no unsafe values |
| **Info** | Well configured, minor improvements possible |
| **Low** | Basic policy with some weaknesses |
| **Medium** | Present but with significant weaknesses |
| **High** | Present but severely misconfigured, protecting little |
| **Critical** | No policy at all |

## Files

| File | Holds |
|---|---|
| `config.go` | What tunes it: identity constants, thresholds and confidence levels. |
| `core.go` | The test itself: `New()`, the orchestration and the assembled verdict. |
| `data.go` | The directive vocabulary: which directives are critical for injection, which values are unsafe, which directives a complete policy sets, and what each of them is for. |

---

The framework this test plugs into, and the conventions every test folder follows, are documented in [`App/SiteTests/Types.go`](../Types.go).
