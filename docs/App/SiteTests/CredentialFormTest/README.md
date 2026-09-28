# Credential Form Analysis

Checks where a page sends the secrets its forms collect. A phishing page exists to collect
credentials, so where it delivers them is the strongest signal on the page itself. A real
site posts a login form to its own backend. A phishing kit usually has no backend: it sends
what the victim typed to a Telegram bot, a Discord webhook, a hosted form service or an
e-mail address, either through the form's `action` or through a script that reads the
fields and calls `fetch`.

|  |  |
|---|---|
| **Test ID** | `credential-form` |
| **Phase** | Response — reads the fetched page; it is the only phase skipped when the main request fails |
| **Category** | Phishing |

```bash
go run ./App/main.go test --target example.com --tests credential-form
```

## What it checks

- Every `<form>` with a field that collects a secret:
  - **password** — `type="password"`, `autocomplete="current-password"` / `new-password`, or a
    name like `password`, `pwd`, `hasło`;
  - **card** — `autocomplete="cc-number"` / `cc-csc` / `cc-exp…`, or a name like
    `cardNumber`, `cvv`, `exp_date`, `numer karty`, a `MM/YY` placeholder;
  - **one-time code** — `autocomplete="one-time-code"`, or a name like `otp`, `smsCode`,
    `2fa`, `pin`, `kod SMS`.

  Names, ids, placeholders and `aria-label`s are split into words first, so `cardNumber`,
  `card_number` and `card-number` read the same. Hidden, checkbox, submit and similar inputs
  are never sensitive.
- Where each such form submits: its `action`, resolved against `<base>` and the page's final
  address, and every `formaction` on its submit buttons.
- Sensitive fields outside any form, which only a script can send anywhere.
- Every inline `<script>` and form `onsubmit` handler that makes a network call (`fetch`,
  `XMLHttpRequest`, `$.ajax`/`$.post`, `axios`, `sendBeacon`, `new Image`, `emailjs.send`)
  and names a data-collection service endpoint.

Commented out markup and non-JavaScript scripts (JSON-LD, templates) are ignored, as the
browser ignores them.

## How it works

1. `modules/markup.go` takes out the inline scripts, splits the rest into forms and finds
   the sensitive fields in and outside them.
2. `modules/destination.go` resolves each action and names its destination, in this order:

| Destination | When |
|---|---|
| `mailto` | A `mailto:` action — the visitor's mail client sends the data as an e-mail |
| `scripted` | A `javascript:` action — a script decides where the data goes |
| `unresolvable` | Not an `http`/`https` URL |
| `collector` | A service from `collectors` — Telegram Bot API, Discord and Slack webhooks, Formspree, Google Forms, Google Apps Script, EmailJS, webhook.site, ngrok… |
| `insecure-http` | Plain `http:` — the data travels unencrypted |
| `same-host` | The page's own hostname; an empty action submits here |
| `same-site` | Another hostname under the page's registered domain |
| `ip-address` | A bare IP address |
| `processor` | An identity provider or payment gateway from `processors` |
| `foreign` | Any other domain |

3. `modules/script.go` finds the collectors each inline script sends to, and whether it
   reads field values (`.value`, `FormData`, `.serialize()`, `.val()`).

## What it reports

| Field | Meaning |
|---|---|
| `PageURL` | The address the page was served from, after redirects |
| `PageDomain` | Its registered domain |
| `FormsScanned` | How many forms the page has |
| `CredentialForms` | Forms collecting a secret: their `Fields` (`Kind`, `Tag`, `Type`, `Name`) and `Submissions` (`Via`, `Method`, `Action`, resolved `URL`, `Host`, `Destination`, `Provider`, `CollectorKind`) |
| `LooseFields` | Sensitive fields outside any form |
| `ScriptSubmissions` | Inline scripts sending to a collector: `Provider`, `CollectorKind`, the `Endpoint` as written, the network calls used and whether field values are read |

The endpoint is reported as written, so a Telegram bot token found in a kit ends up in the
report, where it can be used for a takedown request.

## How the verdict is reached

The verdict is the most severe finding.

| Level | When |
|---|---|
| **None** | Every form collecting a secret submits to the page's own site, or the page collects none |
| **Info** | A form submits to an identity provider or payment gateway, or has a `javascript:` action |
| **Low** | A script on a page without sensitive fields sends to a request catcher or tunnel |
| **Medium** | A form collecting a secret submits to an unrelated domain; or a script on a page without sensitive fields sends to a chat bot |
| **High** | A form collecting a secret submits over plain `http:`, to `mailto:`, to a bare IP address, to a form backend or to a request catcher; or a script on a page with sensitive fields sends to one of the latter two |
| **Critical** | A secret goes to a chat bot or webhook — Telegram, Discord, Slack — through a form or a script |

A script sending to a form backend on a page without sensitive fields is an ordinary contact
form and is not a finding.

Certainty is 100 for form destinations, which are read straight from the page, except for an
unrelated domain, which is 70: single sign-on and payment pages submit elsewhere
legitimately. Script findings are 90 when the script reads field values and 80 when it does
not, because the script is read, not executed.

## Files

| File | Holds |
|---|---|
| `config.go` | Identity constants, certainty levels and how much of the page is scanned. |
| `core.go` | The test itself: `New()`, the severity of each destination and collector, and the assembled verdict. |
| `data.go` | The markup and script patterns, the field name patterns, the autocomplete tokens, the collectors and the processors. Teaching the test a new collector means adding it here. |
| `modules/markup.go` | Extracts forms, sensitive fields, inline scripts and the document base URL. |
| `modules/destination.go` | Resolves a form action and classifies its destination. |
| `modules/script.go` | Finds inline scripts sending data to a collector. |

## Notes

- External scripts are not downloaded, and the page is not rendered, so a kit that builds
  its form or its endpoint at run time, or hides the endpoint in an external or obfuscated
  script, is not seen. `js-obf` covers the obfuscation.
- A collector endpoint split into pieces that are joined at run time is not recognised;
  one written as a whole URL, or with only the token concatenated, is.
- A login form posting to a domain missing from `processors` is reported as `foreign`
  (Medium). Add identity providers and payment gateways there when they show up.

---

The framework this test plugs into, and the conventions every test folder follows, are documented in [`App/SiteTests/README.md`](../README.md).
