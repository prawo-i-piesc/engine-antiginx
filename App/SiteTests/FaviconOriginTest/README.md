# Favicon Origin Analysis

Checks where a page loads its favicon from. A site's icon is one of its own files, served
from its own domain. A phishing page wants the victim's browser tab to show the real brand's
icon, and the cheapest way to get it is not to copy the file but to point at it:
`<link rel="icon" href="https://www.paypal.com/favicon.ico">` on a page served from
`paypal-verify.example`. The same happens by accident when a kit is made by saving the real
login page, and every reference in it keeps pointing at the original site.

|  |  |
|---|---|
| **Test ID** | `favicon-origin` |
| **Phase** | Response — reads the fetched page; it is the only phase skipped when the main request fails |
| **Category** | Phishing |

```bash
go run ./App/main.go test --target example.com --tests favicon-origin
```

## What it checks

- Every `<link>` element whose `rel` declares an icon: `icon`, `shortcut icon`,
  `apple-touch-icon`, `apple-touch-icon-precomposed`, `mask-icon`, `fluid-icon`.
  Commented out markup is ignored, as the browser ignores it.
- The URL each icon resolves to, against the document's `<base>` element when it has one and
  against the page's final address — after redirects — otherwise.
- Which domain that URL belongs to, compared with the page's registered domain.

The icon itself is never downloaded; the test only reads where the page says it is.

## How it works

1. `modules/declarations.go` extracts the icon declarations and the document base URL.
2. `modules/origin.go` resolves each declaration and names its origin, in this order:

| Origin | When |
|---|---|
| `inline` | The icon is a `data:` URI embedded in the page |
| `unresolvable` | Not an `http`/`https` URL, so no browser fetches it as an icon |
| `same-host` | The page's own hostname |
| `same-site` | Another hostname under the page's registered domain, e.g. `static.example.com` |
| `ip-address` | A bare IP address |
| `asset-host` | A CDN or site platform from `assetHostSuffixes` — CloudFront, jsDelivr, Wix, Shopify… |
| `same-organisation` | A domain of the brand that also runs the page, e.g. `fbcdn.net` on `facebook.com` |
| `brand` | A domain of a brand from `brandDomains`, on a page that brand does not run |
| `foreign` | Any other domain |

CDNs are matched before brands, so `cdnjs.cloudflare.com` is a public CDN rather than an
icon borrowed from Cloudflare.

## What it reports

| Field | Meaning |
|---|---|
| `PageURL` | The address the page was served from, after redirects |
| `PageDomain` | Its registered domain |
| `Icons` | Every declared icon: `Rel`, `Href`, resolved `URL`, `Host`, `Origin` and, for brands and platforms, `Provider` |
| `ImpersonatedBrands` | Brands whose domains serve an icon to a page they do not run |

## How the verdict is reached

The verdict is the most severe origin among the declared icons, and it **never rises above
Low**. Icons are loaded from other domains for legitimate reasons — shared assets across an
organisation's domains, partner and reseller pages, embedded integrations — so where an icon
comes from is a signal to weigh next to the other phishing tests (`phishing-url`,
`dns-reputation`), not a verdict on its own.

| Level | When |
|---|---|
| **None** | No icon declared, or every icon is inline, on the page's own site or on another domain of the same brand |
| **Info** | An icon is served by a CDN or site platform, or from an unrelated domain |
| **Low** | An icon is served from a bare IP address, or from a known brand's domain to a page that brand does not run |

Certainty is 100, because where an icon is loaded from is read straight from the page, except
for a brand match, which is 85: the brand may run the page under a domain the dataset does not
list yet.

## Files

| File | Holds |
|---|---|
| `config.go` | Identity constants, certainty levels and how much of the page is scanned. |
| `core.go` | The test itself: `New()`, the severity of each origin and the assembled verdict. |
| `data.go` | The markup patterns, the icon `rel` tokens, the brands and their domains, and the CDNs and platforms. Teaching the test a new brand means adding its domains here. |
| `modules/declarations.go` | Extracts icon declarations and the document base URL. |
| `modules/origin.go` | Resolves a declaration and classifies its origin. |

## Notes

- A brand missing from `brandDomains` is reported as `foreign` (Info), not `brand` (Low).
  Keep the list focused on brands that are actually impersonated, and list every domain a
  brand serves pages and assets from, or the brand's own sites will report their own icons.
- Icons added by JavaScript after load are not seen, because the page is not rendered.

---

The framework this test plugs into, and the conventions every test folder follows, are documented in [`App/SiteTests/README.md`](../README.md).
