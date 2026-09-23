# Detection: protection presence versus blocking

`App/Detection` identifies CDN/WAF fingerprints and anti-bot challenges. Both the scanner's HTTP response handling and the independent bot-protection probe use it. A provider fingerprint alone does **not** mean access was blocked: for example, `CF-RAY` can appear on a normal 200 response. Challenge indicators are what `IsBlocked()` checks.

## API

| Symbol | Behavior |
|---|---|
| `Report` | Holds `Presence []string`, `Challenge []string`, and `StatusCode int` (`0` when there is no response). JSON uses the keys `Presence`, `Challenge` (omitted if empty), and `StatusCode`. |
| `Report.IsBlocked() bool` | True only when `Challenge` is nonempty. |
| `Report.HasProtection() bool` | True when either `Presence` or `Challenge` is nonempty. |
| `Report.All() []string` | Returns challenge indicators followed by presence indicators, or `nil` if both are empty. |
| `FromResponse(resp *http.Response, body string) Report` | Inspects an existing response and the separately supplied body. Returns an empty report for a nil response; does not read `resp.Body`. |
| `Probe(target *url.URL) (Report, error)` | Makes a separate GET request. A nil target, request-construction failure, or network failure returns an error; a non-200 response is still inspected. |
| `FormatList(items []string) string` | Formats one numbered indicator per line, or an empty string for an empty list. |

## Indicators and probing

`FromResponse` records presence from `Server: cloudflare`, nonempty vendor headers (such as `CF-RAY`, `CF-Cache-Status`, `X-Datadome`, and `X-Sucuri-ID`), and body markers such as `__cf_bm` and `/cdn-cgi/challenge-platform`. These markers can occur on accessible pages; header-derived labels may include the header value.

Active mitigation headers (`CF-CHL-BCODE`, `CF-Mitigated`) and distinctive interstitial markers (such as `cf-browser-verification`, `px-captcha`, and `geo.captcha-delivery.com`) count as challenges regardless of status. Generic body phrases such as `captcha`, `access denied`, and `verify you are human` count only on non-200 responses to reduce false positives. A non-200 status by itself is **not** a challenge indicator. `/cdn-cgi/challenge-platform` is a presence marker because normal pages can embed it.

Body matching is case-insensitive and `helpers.RemoveDuplicates` removes repeated labels. Indicators collected from maps have no guaranteed order within `Presence` or `Challenge`, although `All()` always places challenges first.

`Probe` uses browser-like request headers, a 15-second timeout, and reads at most 512 KiB of the body. If reading fails, it still returns header-derived indicators with an empty body and no read error. A 403 or 503 response is data to inspect, not a transport error; probing does not attempt to bypass the protection.

In the scanner, a challenge on a 200 response may prevent content-dependent tests. For a non-200 response, the HTTP wrapper reports the status error and can include any detected indicators. Use `IsBlocked()`, not `HasProtection()`, to test whether a challenge was found.
