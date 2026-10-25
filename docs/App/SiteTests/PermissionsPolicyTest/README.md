# Permissions-Policy Header Analysis

Checks which browser capabilities the page leaves available to itself and to anything it embeds. The header exists so a site can give up powers it does not need — a page with no video call has no reason to keep camera access reachable by an injected script or a third-party frame.

|  |  |
|---|---|
| **Test ID** | `permissions-policy` |
| **Phase** | Response — reads the fetched page; it is the only phase skipped when the main request fails |
| **Category** | Headers |

```bash
go run ./App/main.go test --target example.com --tests permissions-policy
```

## What it checks

- Presence of `Permissions-Policy` and the features it names.
- Features that reach hardware or location, where an unrestricted grant is worth the most.
- Features that tracking and fingerprinting scripts reach for.
- Whether each allowlist actually restricts anything, rather than being present and permissive.

## How it works

1. Read `Permissions-Policy` and split it into `feature=(allowlist)` pairs.
2. For each feature, decide whether its allowlist actually restricts anything: `()` denies
   it outright, `(self)` limits it to the page's own origin, and `*` grants it to everything
   the page embeds.
3. Sort the features into restricted and allowed, and check the allowed ones against the two
   lists in `data.go`.
4. Grade on what remains reachable, weighted by which list it came from.

Only well-formed `feature=allowlist` pairs count as directives; empty parts (a trailing
comma) and anything else are skipped. A header with no valid directive at all — for example
the legacy Feature-Policy syntax `camera 'none'` — is ignored by browsers and graded like a
missing header. The description calls a policy excellent only when it is graded None, and
good only when it is graded Info.

## What it reports

| Key | Meaning |
|---|---|
| `raw_header` | The header as received |
| `total_directives` | How many well-formed directives the policy contains |
| `restricted_features` | Features whose allowlist actually restricts |
| `allowed_features` | Features left reachable |
| `dangerous_allowed` | Of those, the ones reaching hardware, location, the screen, credentials or local data |
| `suspicious_allowed` | Of those, the ones used for tracking and fingerprinting |
| `wildcard_features` | Features granted to everything with `*` |

## How the verdict is reached

| Level | When |
|---|---|
| **None** | Comprehensive policy (5 or more directives) with nothing left open |
| **Info** | Policy present with minor gaps, e.g. one tracking feature delegated |
| **Low** | No policy header, a header with no valid directive, a minimal policy (fewer than 3 directives), dangerous features unrestricted or granted with `*` (however many), or two or more tracking features open |

Calibrated to OWASP ZAP alert 10063 (Permissions Policy header not set, Low); see the SiteTests overview for the severity scale.

## Files

| File | Holds |
|---|---|
| `config.go` | What tunes it: identity constants, thresholds and confidence levels. |
| `core.go` | The test itself: `New()`, the `PermissionsPolicyAnalysis` it reports as metadata, and the analyze, evaluate and describe stages it plugs into the shared `SiteTests.HeaderTest`. |
| `data.go` | The two feature lists the policy is graded against, split by what an unrestricted grant actually costs the visitor. |
| `core_test.go` | Unit tests for grading and descriptions across valid, weak, invalid and missing values. |

---

The shared framework and test conventions are described in the [SiteTests overview](../README.md).
