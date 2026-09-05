# Cross-Origin Security Headers Analysis

Reads the three headers that decide how far the page is isolated from other origins sharing the browser process. They are what closes the door on Spectre-style side-channel reads and on other sites embedding the page's resources — and they are also the precondition for a site to use the browser's high-resolution timers at all.

|  |  |
|---|---|
| **Test ID** | `cross-origin-x` |
| **Phase** | Response — reads the fetched page; it is the only phase skipped when the main request fails |
| **Category** | Headers |

```bash
go run ./App/main.go test --target example.com --tests cross-origin-x
```

## What it checks

- `Cross-Origin-Embedder-Policy` — whether the page requires everything it loads to opt in.
- `Cross-Origin-Resource-Policy` — who is allowed to load this response.
- `Cross-Origin-Opener-Policy` — whether the page keeps its own browsing context group.
- Values that are present but permissive, which configure the header without gaining the protection.

## How it works

1. Read all three headers.
2. Judge each on its own: whether it is present, and whether its value is one of the strict
   ones (`require-corp`, `same-origin`) or one of the permissive ones (`unsafe-none`,
   `cross-origin`).
3. Count how many are configured strictly, and report whether the combination amounts to
   cross-origin isolation — which needs COEP and COOP together, not either alone.

## What it reports

| Key | Meaning |
|---|---|
| `hasCOEP` / `hasCORP` / `hasCOOP` | Whether each header is present |
| `coepValue` / `corpValue` / `coopValue` | The values as received |
| `configuredHeaders` | How many of the three are set |
| `missingHeaders` | Which are absent |
| `isolationEffective` | Whether the combination achieves cross-origin isolation |
| `protectionLevel` | `Excellent`, `Good`, `Basic` or `None` |
| `securityIssues` | What is wrong, in the operator's terms |
| `recommendedActions` | What to set instead |

## How the verdict is reached

| Level | When |
|---|---|
| **None** | All three headers set to strict values |
| **Info** | Two headers configured securely |
| **Low** | One header configured, or the values are less strict |
| **Medium** | Headers present but permissive |
| **High** | No cross-origin headers at all |

## Files

| File | Holds |
|---|---|
| `config.go` | What tunes it: identity constants, thresholds and confidence levels. |
| `core.go` | The test itself: `New()`, the orchestration and the assembled verdict. |

---

The framework this test plugs into, and the conventions every test folder follows, are documented in [`App/SiteTests/Types.go`](../Types.go).
