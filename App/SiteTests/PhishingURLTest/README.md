# Phishing URL Analysis

Analyses the URL itself, along two independent dimensions: who the hostname pretends to be, and what the rest of the URL carries. Both are needed, because a phishing link can use a perfect lookalike domain with harmless parameters, or a throwaway domain with a fully assembled credential-harvesting query string.

|  |  |
|---|---|
| **Test ID** | `phishing-url` |
| **Phase** | PreResponse — runs from the target URL alone, in parallel with the page fetch, so it still reports when the target is unreachable or blocked |
| **Category** | Phishing |

```bash
go run ./App/main.go test --target example.com --tests phishing-url
```

## What it checks

- **Hostname impersonation** — single-character typos, adjacent-character transpositions, letter substitutions attackers favour (`rn` for `m`, `1` for `l`), and homograph attacks using Unicode characters that render like ASCII letters.
- **URL parameters** — credentials embedded in the URL, session and payment data in the query string, victim identity used to pre-fill a landing page, brand keywords claimed outside the hostname, open-redirect targets pointing off-site, base64-hidden URLs and addresses, dangerous schemes such as `javascript:` and `data:`, and structural anomalies like an IP literal host or an oversized query.

## How it works

The two dimensions run independently, one per file in `modules/`.

**Hostname** (`domainimpersonation.go`) compares the host against the brand dataset:
- exact match against a known-legitimate domain, which ends the analysis in the target's favour
- single-character edit distance — one insertion, deletion or substitution
- adjacent-character transposition (`goolge`)
- the letter-replacement table (`rn` for `m`, `1` for `l`, `0` for `o`)
- homograph detection: characters are normalised through the confusable map and re-compared,
  so a Cyrillic `а` in `pаypal.com` is caught even though the two strings differ in every byte

**Parameters** (`urlparameters.go`) walks the query string, the userinfo and the path,
matching parameter names against four databases and their values against the dangerous
scheme list. Base64-looking values are decoded and re-examined, which is what catches a
redirect target or a victim's e-mail address hidden one encoding deep.

`core.go` then combines the two verdicts and assembles the metadata.

## What it reports

Two nested objects plus the fields needed for a quick verdict:

| Key | Meaning |
|---|---|
| `url` | The analysed URL, **redacted** |
| `host` | The hostname analysed |
| `is_suspicious` | Whether either dimension found anything |
| `detected_patterns` | Every indicator from both dimensions |
| `domain_analysis` | `matched_brand`, `matched_legitimate_domain`, `is_known_legitimate`, `lookalike_examples`, `homograph_char_count` |
| `parameter_analysis` | `parameter_count`, `credential_parameters`, `sensitive_parameters`, `identity_parameters`, `external_redirect_parameters`, `dangerous_scheme_parameters`, `encoded_payload_parameters`, `brand_keywords_in_url`, `structural_indicators`, `embedded_credentials`, `credential_values_present` |

Parameter **names** appear; parameter **values** never do.

## How the verdict is reached

- Each dimension is judged on its own and the higher classification wins, so a finding in either is never diluted by a clean result in the other.
- When **both** dimensions reach Medium, the result is escalated by one level: a lookalike hostname that also harvests data describes a complete phishing page rather than an isolated anomaly.

## Files

| File | Holds |
|---|---|
| `config.go` | What tunes it: identity constants, thresholds and confidence levels. |
| `core.go` | The test itself: `New()`, the orchestration and the assembled verdict. |
| `data.go` | The brand and domain datasets, the letter-replacement table, the confusable-character map and the parameter name databases. This is the part of the test that dates fastest and is meant to be edited often. |
| `modules/domainimpersonation.go` | The hostname dimension. |
| `modules/shared.go` | Helpers both dimensions use. |
| `modules/urlparameters.go` | The parameter dimension. |

## Notes

Parameter values are never copied into the result. Only parameter names and a redacted form of the URL are reported, so a scan report can never leak the very credentials this test warns about.

---

The framework this test plugs into, and the conventions every test folder follows, are documented in [`App/SiteTests/Types.go`](../Types.go).
