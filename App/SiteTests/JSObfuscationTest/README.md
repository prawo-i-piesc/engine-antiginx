# JavaScript Obfuscation Detection

Looks for JavaScript written to be unreadable. Minification makes code smaller; obfuscation makes it opaque, and a page that hides what its script does is worth a second look — phishing kits obfuscate to keep their credential-harvesting logic out of sight of scanners and casual inspection.

|  |  |
|---|---|
| **Test ID** | `js-obf` |
| **Phase** | Response — reads the fetched page; it is the only phase skipped when the main request fails |
| **Category** | Phishing |

```bash
go run ./App/main.go test --target example.com --tests js-obf
```

## What it checks

- Script bodies extracted from the page's `<script>` elements.
- String-to-code entry points: `eval`, `Function`, and string arguments to `setTimeout`/`setInterval`.
- Decoders — `atob`, `unescape`, `String.fromCharCode` — and especially a decoder feeding straight into `eval`.
- Hex and Unicode escape sequences used in place of readable characters.
- Long base64 literals, concatenated string fragments and bracket-notation access to execution entry points.
- Decoders applied to other decoders, which is layering rather than encoding.
- Keywords that speak to intent rather than technique — `shell`, `payload`, `exploit`, `backdoor`.

## How it works

1. Extract the body of every `<script>` element from the page.
2. Run each detector in `modules/detectors.go` over the concatenated script source. Every
   detector reports both *whether* its technique appears and *how much*, because volume is
   what separates a bundler from a kit — one `\x41` escape is nothing, four hundred is a
   decision.
3. Score in `modules/scoring.go`: each technique contributes weighted by its count, and
   combinations score above the sum of their parts. A decoder alone is ordinary; a decoder
   feeding `eval` is not.
4. Map the score to an obfuscation level, then to a threat level, raised when malicious
   indicators are present.

## What it reports

| Field | Meaning |
|---|---|
| `hasObfuscation` | Whether anything was detected at all |
| `obfuscationScore` | 0–100 |
| `obfuscationLevel` | `none`, `light`, `moderate`, `heavy` or `extreme` |
| `obfuscationPatterns` | Techniques found |
| `suspiciousPatterns` | Patterns that are suspicious in combination |
| `maliciousIndicators` | Findings that speak to intent rather than technique |
| `encodingMethods` | Which decoders the page uses |
| `dynamicExecution`, `encodedStrings`, `charCodeUsage`, `hexEscapes`, `unicodeEscapes`, `base64Strings` | Counts per technique |
| `certainty` | 0–100 |

## How the verdict is reached

| Level | When |
|---|---|
| **None** | Clean, readable JavaScript |
| **Info** | Minification or ordinary build output |
| **Low** | Some patterns present but likely legitimate, such as a webpack bundle |
| **Medium** | Several suspicious patterns together |
| **High** | Heavy obfuscation with clear intent to conceal |
| **Critical** | Extreme obfuscation alongside malicious indicators |

## Files

| File | Holds |
|---|---|
| `config.go` | What tunes it: identity constants, thresholds and confidence levels. |
| `core.go` | The test itself: `New()`, the orchestration and the assembled verdict. |
| `data.go` | Every expression the detectors match against, compiled once at start up. Tuning what counts as obfuscation means editing this table, not the detectors. |
| `modules/detectors.go` | The individual detectors, one per technique. |
| `modules/scoring.go` | Weighs the detections into a score and an obfuscation level. |

## Notes

Legitimate bundlers produce code that trips several of these detectors, which is why the lower bands exist and why a single detection never reaches a high threat level on its own.

---

The framework this test plugs into, and the conventions every test folder follows, are documented in [`App/SiteTests/Types.go`](../Types.go).
