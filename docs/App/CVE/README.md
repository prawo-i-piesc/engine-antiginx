# CVE: rating known vulnerabilities with CVSS

`App/CVE` asks the NIST National Vulnerability Database (CVE API 2.0) which CVEs affect a
technology, and rates them the way CVE records are rated: with the
[CVSS](https://www.first.org/cvss/) qualitative severity scale, as NVD publishes it. The
server-header test uses it for every release it finds disclosed.

## API

| Symbol | Purpose |
|---|---|
| `NewCVEClient() *CVEClient` | A client with a 30-second timeout, the endpoint `https://services.nvd.nist.gov/rest/json/cves/2.0` or the one in `ANTIGINX_NVD_URL` (`BaseURLEnv`), and the API key in `ANTIGINX_NVD_API_KEY` (`APIKeyEnv`), sent as the `apiKey` header when set. |
| `(*CVEClient).AssessTechnologyVulnerabilities(technology, version string) (*VulnerabilityAssessment, error)` | Finds and rates the CVEs. Fails if the request, the read or the JSON decoding fails, or NVD answers other than 200. |
| `SeverityFromScore(cvssVersion string, score float64) string` | The CVSS qualitative rating of a base score under that CVSS version. |
| `MoreSevere(a, b string) bool` | Orders two ratings. |
| `ProductFor(technology string) (Product, bool)` | The verified CPE vendor and product of a detected technology. |
| `IsReleaseVersion(version string) bool` | Whether a disclosed version is concrete enough to look a release up by. |
| `GetThreatLevelFromAssessment(assessment) int` | The assessment's risk level as an engine threat-level number. |

## Which CVEs: matching a release

A CVSS score rates one vulnerability, so it only says something about a server if that
vulnerability affects the release the server runs. How the CVEs are found decides that:

| `matched_by` | When | Query | What the results mean |
|---|---|---|---|
| `cpe` | The technology has a verified CPE product and `version` is a release number | `virtualMatchString=cpe:2.3:a:<vendor>:<product>:<version>`, up to 2000 results | The CVEs NVD records as affecting that release, version ranges included |
| `keyword` | Otherwise | `keywordSearch=<name> [version]`, up to 100 results | CVEs whose description mentions the technology; nothing says they affect any particular release |

Every query carries `noRejected`, and a CVE whose `vulnStatus` is `Rejected` is dropped in
any case: a rejected CVE ID is not a vulnerability.

The verified products (`products.go`) were each checked against NVD by looking up a release
with a known CVE:

| Technology | CPE vendor:product | Checked with |
|---|---|---|
| Apache | `apache:http_server` | 2.4.49 → CVE-2021-41773 |
| Nginx | `f5:nginx` | 1.18.0 → CVE-2021-23017 |
| Microsoft IIS | `microsoft:internet_information_services` | 7.5 → CVE-2010-2730 |
| PHP | `php:php` | 7.4.3 → 30 CVEs |
| Gunicorn | `gunicorn:gunicorn` | 19.4.5 → CVE-2018-1000164 |
| Uvicorn | `encode:uvicorn` | 0.11.6 → CVE-2020-7695 |
| WordPress | `wordpress:wordpress` | 5.0 → CVE-2018-20147 |
| Drupal | `drupal:drupal` | 7.0 → CVE-2011-2687 |

To add one, find a CVE affecting the product, read its `configurations` in NVD for the
`cpe:2.3:a:vendor:product` it uses, and confirm a `virtualMatchString` lookup of an affected
release returns that CVE.

A CVE NVD has not analysed yet (`Received`, `Awaiting Analysis`, `Deferred`) has no
affected-version data, so a CPE lookup cannot find it. This is a limit of NVD's data, and the
reason the test reports what NVD records rather than claiming a release is free of CVEs.

## How a CVE is rated

NVD can carry several scorings of one CVE: its own (`type: "Primary"`, source
`nvd@nist.gov`) and the publishing CNA's (`type: "Secondary"`), under CVSS 4.0, 3.1, 3.0 and
2.0. NVD lists the CNA's scoring before its own about as often as after it. The client
rates a CVE by:

1. NVD's own scoring, in the newest CVSS version NVD scored it under; or, while NVD has not
   scored it,
2. the CNA's scoring in the newest CVSS version available.

`score`, `cvss_version`, `vector` and `scored_by` record which scoring that was. The
`severity` is computed from the score with the scale of its CVSS version, so a missing label
or one that contradicts its score cannot skew it:

| Rating | CVSS 3.x and 4.0 | CVSS 2.0 (NVD) |
|---|---|---|
| `NONE` | 0.0 | — |
| `LOW` | 0.1–3.9 | 0.0–3.9 |
| `MEDIUM` | 4.0–6.9 | 4.0–6.9 |
| `HIGH` | 7.0–8.9 | 7.0–10.0 |
| `CRITICAL` | 9.0–10.0 | — |

CVSS 2.0 has no Critical: a 10.0 under 2.0 is `HIGH`. A CVE with no scoring at all has the
rating `""` (unscored), which is not `LOW` — nothing is known about its severity yet.

## How an assessment is rated

CVSS rates each vulnerability on its own and defines no way of combining several. The
assessment is therefore rated by its most severe CVE, and the counts are reported beside the
rating, never folded into it: three `MEDIUM` CVEs are a `MEDIUM` assessment.

| `risk_level` | When | `GetThreatLevelFromAssessment` |
|---|---|---|
| `CRITICAL` | The most severe CVE is rated `CRITICAL` | 5 |
| `HIGH` | … `HIGH` | 4 |
| `MEDIUM` | … `MEDIUM` | 3 |
| `LOW` | … `LOW` | 2 |
| `UNSCORED` | CVEs found, none scored yet | 1 |
| `NONE` | No CVE, or only CVEs scored 0.0 | 0 |

`max_score` is the score of the most severe CVE — a 10.0 under CVSS 2.0 does not stand
behind a `CRITICAL` rated under 3.1. `total_results` is what NVD reports matching;
`cve_count` what was received and kept.

The rating describes the vulnerabilities, not the risk to a particular deployment: CVSS
leaves that to the organisation using it, and a CPE match does not know whether the
vulnerable feature is enabled.

## Rate limits

Without an API key NVD allows five requests per rolling 30 seconds, and answers more with
403; with a key (free from NVD), fifty. Set `ANTIGINX_NVD_API_KEY` for scans that disclose
several releases.

## Tests

`App/CVE/UnitTests` runs the client against a local stand-in for the NVD API
(`UnitTestKit.ServeNVD`):

- two real NVD responses retrieved on 2026-10-25 — nginx 1.18.0 (6 CVEs, most severe HIGH
  7.8) and PHP 7.4.3 (30 CVEs, CRITICAL 9.8) — trimmed to the fields the client reads;
- prepared edge cases (`CVE-2099-…`, invented): a CNA's Critical listed before NVD's High,
  a CNA's CVSS 4.0 beside NVD's 3.1, a 10.0 under CVSS 2.0, a CNA-only scoring without a
  label, an unscored CVE, a rejected CVE, a 0.0 and a label contradicting its score;
- the CVSS scale at every band edge, no escalation by count, unscored-only and empty
  results, the queries sent (CPE or keyword, `noRejected`, the API key) and failures.
