# URLhaus Malicious URL Lookup

Looks the target up in [URLhaus](https://urlhaus.abuse.ch/), the abuse.ch database of URLs used to distribute malware. URLhaus is free, community-fed and updated continuously, which makes it a cheap second opinion: the engine's other tests judge how a site looks, this one asks whether anybody has already caught it serving malware.

|  |  |
|---|---|
| **Test ID** | `urlhaus` |
| **Phase** | PreResponse — needs only the target URL, so it still reports when the target is unreachable or blocked |
| **Category** | Phishing |

```bash
ANTIGINX_URLHAUS_AUTH_KEY=<key> go run ./App/main.go test --target example.com --tests urlhaus
```

## What it checks

- Whether the **exact URL** is listed, and whether it is still online.
- Whether the **host** has URLs listed, how many, and how many are still online.
- How Spamhaus DBL and SURBL classify the domain, as URLhaus reports it — in particular
  whether it is a **legitimate service that was abused** (a file host, a code forge, a URL
  shortener) rather than a domain run for abuse.

## How it works

1. Strip credentials and the fragment from the target URL — they never leave the engine —
   and lowercase its scheme and host the way URLhaus stores them; the path keeps its case.
2. `POST /v1/url/` with the URL, then `POST /v1/host/` with the hostname, both carrying the
   `Auth-Key` header.
3. Treat `query_status` `ok` as listed and `no_results` as not listed. Any other status, a
   non-200 answer or unreadable JSON fails the lookup: the test then reports **Info**, never
   a clean result, because a half answer must not read as a safe one.
4. Grade as below and copy up to 10 of the host's listed URLs, online ones first, into the
   metadata.

## How the verdict is reached

| Level | When |
|---|---|
| **Critical** | The exact URL is listed and online, or the host has online URLs and is blocklisted as malicious |
| **High** | The exact URL is listed but offline, or the host has online URLs listed |
| **Medium** | The host has only offline URLs listed |
| **Low** | The host is an abused legitimate service with online URLs listed |
| **Info** | The host is an abused legitimate service with only offline URLs, or no lookup was possible |
| **None** | Neither the URL nor the host is listed |

A Spamhaus DBL classification of `spammer_domain`, `phishing_domain` or `botnet_cc_domain`,
or a SURBL listing, raises a host finding by one level. An `abused_legit_*` or
`abused_redirector` classification lowers it instead: `github.com` hosting somebody's
payload says nothing about a project page on it. The exact URL being listed always
outweighs the host classification.

| Certainty | When |
|---|---|
| 100 | The exact URL is listed, or no lookup was made — the result says exactly that |
| 90 | The host is listed |
| 80 | Nothing is listed; one blocklist cannot prove a site safe |
| 70 | The host is an abused legitimate service |

## What it reports

| Field | Meaning |
|---|---|
| `checked` | Whether both lookups succeeded |
| `lookup_error` | Why not, when they did not |
| `url`, `host` | What was sent to URLhaus |
| `url_listed`, `url_entry` | The URL's own entry: `url_status`, `threat`, `tags`, `date_added`, `urlhaus_reference` |
| `host_listed`, `host_reference` | Whether the host is known, and its URLhaus page |
| `host_url_count`, `host_online_urls` | URLs recorded for the host in total, and how many of the returned ones are online |
| `host_urls` | Up to 10 of them, online first |
| `blacklists` | `spamhaus_dbl` and `surbl` as URLhaus reports them |
| `abused_legitimate`, `malicious_listing` | The two readings of those listings that change the grade |

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `ANTIGINX_URLHAUS_AUTH_KEY` | — | abuse.ch Auth-Key, free from the [abuse.ch Authentication Portal](https://auth.abuse.ch/). Required by the API since 2025; without it the test reports **Info** and makes no request. |
| `ANTIGINX_URLHAUS_URL` | `https://urlhaus-api.abuse.ch` | API entry point, for a mirror or a local test server. |

## Files

| File | Holds |
|---|---|
| `config.go` | Identity constants, certainty levels, timeout and size limits, the environment variable names. |
| `core.go` | `New()`, reading the environment and the assembled verdict. |
| `data.go` | The Spamhaus DBL classifications read as abused-legitimate and as malicious. |
| `modules/urlhaus.go` | The two API calls, the response types, grading and the description. |
| `modules/urlhaus_test.go` | Tests against a fake URLhaus server: clean, listed, abused host, failed lookups. |

## Notes

**The target is sent to a third party.** Every scan discloses the scanned URL, query string
included, to abuse.ch. The query string is kept because URLhaus stores full URLs and a
payload is often told apart by its parameters.

**Absence is weak evidence.** URLhaus tracks malware distribution, not phishing in general,
so a credential-harvesting page can be unlisted. Read a clean result together with the
`phishing-url` and `dns-reputation` findings.

---

The shared framework and test conventions are described in the [SiteTests overview](../README.md).
