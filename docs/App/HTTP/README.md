# HTTP: fetching the scan target

`App/HTTP` provides `CreateHttpWrapper(opts ...WrapperOption)` and `Get(url string, opts ...WrapperOption) *http.Response`. The wrapper type is unexported but usable through the returned value. `Get` makes a request with a 30-second client timeout, reads the entire body, restores a readable body for the caller, and passes the response to `Detection.FromResponse`. It panics with an `HttpError` on failure; the strategy layer can convert that value into `RequestInfo`.

## Configuration

The default header is `User-Agent: AntiGinx/1.0`. `WithHeaders(map[string]string)` adds or overrides configured headers. `WithAntiBotDetection()` fills in missing browser-like headers and, when applied at construction, configures TLS 1.2–1.3, HTTP/2 attempts, connection pooling, and a cookie jar if creation succeeds. Certificate verification remains enabled. With anti-bot mode active, `Get` delays the request by 1 to less than 3 seconds and selects a random user agent from a built-in list. Setting headers on a Go request does not guarantee their wire order or bypass bot protection.

**Per-call option caveat:** `Get` applies options to a shallow copy of its configuration, so the headers map remains shared with the wrapper. Passing `WithHeaders` to `Get` changes headers for subsequent requests too; concurrent map writes are not synchronized. Passing `WithAntiBotDetection` only to `Get` adds its headers to the shared map and enables the delay and random user agent, but does not retrofit the transport or cookie jar. Use constructor options for lasting client settings. In anti-bot mode, the random user agent replaces any configured user agent for that request.

## Responses and errors

`Get` reads the body before checking status so detection can inspect challenge markup. On a successfully read response, it replaces the body with a readable buffered copy. It accepts **only status 200**, not other 2xx statuses. CDN/WAF fingerprints alone do not stop a 200 response. A detected challenge on a 200 response causes an error only when anti-bot mode is off; with that mode on, `Get` returns the response even if detection marks it blocked.

| `HttpError.Code` | Condition | `IsRetryable` |
|---|---|---|
| `100` | Request creation failed. | `false` |
| `101` | `client.Do` failed (for example, a network error or timeout). | `true` |
| `200` | Reading the response body failed. | `false` |
| `102` | Status is not 200; `Protections` contains any detected indicators. | `false` |
| `300` | Challenge detected on a 200 response while anti-bot mode is off. | `false` |

`HttpError` carries `Url`, `Code`, `Message`, the original `Error`, `IsRetryable`, and `Protections`. Detection identifies providers and challenges; the HTTP wrapper decides whether to return or reject the response. Strategies use these fields when reporting skipped response tests and possible bot-protection findings; see [execution](../execution/README.md).
