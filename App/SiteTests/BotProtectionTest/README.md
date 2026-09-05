# Bot Protection Block Assessment

Identifies the CDN, WAF or bot-protection layer sitting in front of the target, and whether it withholds content behind a challenge. It issues its own probe rather than reading the main response, for two reasons: it has to reach a verdict precisely when the main request was blocked and there is no response to inspect, and keeping the detection out of the transport layer stops a CDN fingerprint from deciding the fate of the whole scan.

|  |  |
|---|---|
| **Test ID** | `bot-protection` |
| **Phase** | PreResponse — runs from the target URL alone, in parallel with the page fetch, so it still reports when the target is unreachable or blocked |
| **Category** | Bot-Protection |

```bash
go run ./App/main.go test --target example.com --tests bot-protection
```

## What it checks

- Vendor fingerprints in headers and page content.
- Whether a challenge was served instead of the content — a different statement from merely being proxied.
- The status the probe was answered with, and whether the target answered at all.

## How it works

**`New()` — the test.** Issues its own GET with a plain user agent and no evasion, then
classifies the answer along two axes that are deliberately not merged: *presence* (a vendor
fingerprint in the headers or body, meaning the target is proxied) and *challenge* (an
interstitial served instead of content). Collapsing the two is what previously made every
Cloudflare-fronted site look blocked.

**`NewVerdict()` — the fallback.** The scheduler calls this when the main request was
stopped by a protection layer, so no Response-phase test has anything to read. It turns the
transport failure into a finding, distinguishing HTTP 102 (a challenge was served) from 300
(protection detected in front of a normal answer).

Only one of the two ever appears in a report: when the scan already includes this test, the
scheduler leaves the verdict to it rather than synthesising a competing finding with the
same name.

## What it reports

From the test — `Presence` (vendors identified), `Challenge` (evidence content was
withheld), `StatusCode`, `Blocked`, `Reachable`.

From the verdict — `Protections`, `BlockMessage`, `HttpErrorCode`, and `OriginTested`,
which is always `false` and is stated explicitly so no consumer can mistake a block for a
completed assessment.

## How the verdict is reached

| Level | When |
|---|---|
| **Info** | Target unreachable, or no protection layer identified |
| **Low** | A protection layer was identified, whether or not it challenged the probe |

## Files

| File | Holds |
|---|---|
| `config.go` | What tunes it: identity constants, thresholds and confidence levels. |
| `core.go` | The test itself: `New()`, the orchestration and the assembled verdict. |
| `data.go` | What it knows: the reference datasets it recognises the world against. |

## Notes

A protection layer is reported at Low rather than as a vulnerability because it is weak evidence about legitimacy, not a misconfiguration: a commercial protection product has to be set up by whoever controls the domain, which throwaway phishing infrastructure rarely bothers with. The package also exports `NewVerdict()`, which the scheduler calls when a protection layer stopped the main request — the block itself is then the only evidence available, and it is worth reporting rather than discarding.

---

The framework this test plugs into, and the conventions every test folder follows, are documented in [`App/SiteTests/Types.go`](../Types.go).
