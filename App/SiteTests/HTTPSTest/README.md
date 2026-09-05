# HTTPS Protocol Verification

Reports whether the target was actually reached over TLS. It is the smallest test in the engine and the one every other encryption finding is read against: HSTS, certificate strength and secure cookies all describe protections that do nothing if the connection itself is plaintext.

|  |  |
|---|---|
| **Test ID** | `https` |
| **Phase** | Response — reads the fetched page; it is the only phase skipped when the main request fails |
| **Category** | Encryption |

```bash
go run ./App/main.go test --target example.com --tests https
```

## What it checks

- The scheme of the URL the response came back on, after any redirects the client followed.

## How it works

The test reads `params.Response.Request.URL.Scheme`. That is the URL the HTTP client
actually ended up on, so a site that redirects `http://` to `https://` is judged on where
it landed, not on where the scan started.

Note that the engine downgrades the scanned URL to `http://` when this test or `hsts` is
part of the selection — otherwise the redirect would never be observed and every target
would trivially pass.

## What it reports

Nothing. This test reports `Metadata: nil`: the scheme is already stated in the
description, and there is no second fact worth carrying.

## How the verdict is reached

| Level | When |
|---|---|
| **None** | The response arrived over `https` |
| **High** | The response arrived over `http`, so everything on the page travelled in the clear |

## Files

| File | Holds |
|---|---|
| `config.go` | What tunes it: identity constants, thresholds and confidence levels. |
| `core.go` | The test itself: `New()`, the orchestration and the assembled verdict. |
| `data.go` | The two verdict texts, kept out of the logic so their wording can be reviewed without touching the code that picks between them. |

## Notes

Certainty is always 100%: the scheme either is `https` or it is not, so there is no case where this test is only partly sure.

---

The framework this test plugs into, and the conventions every test folder follows, are documented in [`App/SiteTests/Types.go`](../Types.go).
