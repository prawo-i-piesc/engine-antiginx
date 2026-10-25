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

- Script bodies extracted from the page's `<script>` elements, or the whole response when it is
  served as JavaScript (`Content-Type` naming `javascript` or `ecmascript`).
- String-to-code entry points: `eval`, `Function`, and string arguments to `setTimeout`/`setInterval`.
- Decoders — `atob`, `unescape`, `String.fromCharCode` — and especially a decoder feeding straight into `eval`.
- Hex and Unicode escape sequences used in place of readable characters.
- Long base64 literals, concatenated string fragments and bracket-notation access to execution entry points.
- Decoders applied to other decoders, which is layering rather than encoding.
- Keywords that speak to intent rather than technique — `shell`, `payload`, `exploit`, `backdoor`.
- Malicious indicators — code that runs decoded content: `eval` of a decoder, decoders applied
  to decoders, nested `eval`, `document.write` of decoded markup, a string handed to
  `setTimeout`/`setInterval`, self-decrypting loops, and intent keywords in obfuscated code.

## How it works

1. Extract the body of every `<script>` element from the page. A response served as JavaScript
   is taken as one script as a whole.
2. Run each detector in `modules/detectors.go` over the concatenated script source. Every
   detector reports both *whether* its technique appears and *how much*, because volume is
   what separates a bundler from a kit — one `\x41` escape is nothing, four hundred is a
   decision.
3. Score in `modules/scoring.go`: each technique contributes weighted by its count, and
   combinations score above the sum of their parts. A decoder alone is ordinary; a decoder
   feeding `eval` is not.
4. Map the score to an obfuscation level. The threat level comes from the malicious
   indicators; without any, obfuscation of any degree is at most Low.

## What it reports

| Field | Meaning |
|---|---|
| `hasObfuscation` | Whether the score reaches the obfuscation threshold (20), the same point where the level becomes `light` and the grade Low |
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
| **Info** | Minification or ordinary build output (score 10–19, below the threshold, so `hasObfuscation` is false) |
| **Low** | Obfuscated — score from 20 (`ObfuscationThreshold` in `modules/scoring.go`), whatever the degree — but no malicious indicator |
| **Medium** | One malicious indicator |
| **High** | Two or more independent malicious indicators |

Nothing is Critical: that level is reserved for CVEs rated Critical by CVSS.

Grades evidence that the page itself is malicious, not a weakness of the site: obfuscation on its own is not a vulnerability; see the SiteTests overview for the severity scale.

## Files

| File | Holds |
|---|---|
| `config.go` | What tunes it: identity constants, thresholds and confidence levels. |
| `core.go` | The test itself: `New()`, the orchestration and the assembled verdict. |
| `data.go` | Every expression the detectors match against, compiled once at start up. Tuning what counts as obfuscation means editing this table, not the detectors. |
| `modules/detectors.go` | The individual detectors, one per technique. |
| `modules/scoring.go` | Weighs the detections into a score and an obfuscation level. |

## Notes

Legitimate bundlers produce code that trips several of these detectors, which is why obfuscation without a malicious indicator never rises above Low.

---

The shared framework and test conventions are described in the [SiteTests overview](../README.md).
