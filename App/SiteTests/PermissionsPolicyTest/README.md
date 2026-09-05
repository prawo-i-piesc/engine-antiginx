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

## What it reports

| Key | Meaning |
|---|---|
| `raw_header` | The header as received |
| `total_directives` | How many features the policy names |
| `restricted_features` | Features whose allowlist actually restricts |
| `allowed_features` | Features left reachable |
| `dangerous_allowed` | Of those, the ones reaching hardware or location |
| `suspicious_allowed` | Of those, the ones used for tracking and fingerprinting |
| `wildcard_features` | Features granted to everything with `*` |

## How the verdict is reached

| Level | When |
|---|---|
| **None** | Comprehensive policy with the dangerous features restricted |
| **Info** | Policy present with minor gaps |
| **Low** | Basic policy, some features left open |
| **Medium** | Policy present but dangerous features are unrestricted |
| **High** | No policy header at all |

## Files

| File | Holds |
|---|---|
| `config.go` | What tunes it: identity constants, thresholds and confidence levels. |
| `core.go` | The test itself: `New()`, the orchestration and the assembled verdict. |
| `data.go` | The two feature lists the policy is graded against, split by what an unrestricted grant actually costs the visitor. |

---

The framework this test plugs into, and the conventions every test folder follows, are documented in [`App/SiteTests/Types.go`](../Types.go).
