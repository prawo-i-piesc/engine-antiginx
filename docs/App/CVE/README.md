# CVE: searching the NVD

`App/CVE` searches the NIST National Vulnerability Database (CVE API 2.0) for a technology and optional version, then summarizes the returned matches. The server-header test uses this assessment when evaluating detected technologies.

## API

| Symbol | Purpose |
|---|---|
| `NewCVEClient() *CVEClient` | Creates an NVD client with a 30-second timeout and the endpoint `https://services.nvd.nist.gov/rest/json/cves/2.0`, or the one named by `ANTIGINX_NVD_URL` (`CVE.BaseURLEnv`) — an NVD mirror, or a local server serving prepared responses in tests. |
| `(*CVEClient).AssessTechnologyVulnerabilities(technology, version string) (*VulnerabilityAssessment, error)` | Searches and summarizes the matches. Returns `nil` and an error if the request, response read, or JSON decoding fails, or if NVD returns a non-200 status. The assessment retains the original technology name and version. |
| `GetThreatLevelFromAssessment(assessment *VulnerabilityAssessment) int` | Maps the assessment's `RiskLevel` to a numeric threat level. Pass a non-nil assessment. |

```go
client := CVE.NewCVEClient()
assessment, err := client.AssessTechnologyVulnerabilities("nginx", "1.21.0")
if err != nil {
    fmt.Println("NVD lookup failed:", err)
} else {
    fmt.Println(assessment.CVECount, assessment.RiskLevel)
}
```

## Search behavior and limitations

- `normalizeTechnologyName` maps exact, case-sensitive names such as `Apache` to `apache http server` and `Microsoft IIS` to `internet information services`. Other names are lowercased; this is not CPE validation.
- `buildSearchQuery` joins the normalized name and version with a space. An empty version or the literal string `"detected"` searches by name alone. The request sets `keywordSearch`, `resultsPerPage=100`, `Accept: application/json`, and `User-Agent: AntiGinx-CVE-Client/1.0`.
- This is a **keyword search**, not proof that a CVE affects the supplied version. The client does not check affected version ranges or fetch additional pages. `CVECount` is the number of results processed from the single response (at most 100), not NVD's `totalResults`.

`NVDResponse` decodes the CVE API 2.0 shape: the vulnerability list, pagination fields, the zone-less `published`/`lastModified` timestamps (read as UTC; an unreadable one becomes the zero time instead of failing the response), the `descriptions` array, `references` and the CVSS metrics. The converter takes the first English description, every reference URL, and the score and uppercase severity of the newest CVSS version the vulnerability was scored under — 4.0, then 3.1, 3.0 and 2.0, whose severity sits beside `cvssData` rather than in it. Without any metric, score and severity keep their zero values.

## Assessment and risk

`CVEResult` exposes the JSON fields `id`, `description`, `severity`, `score`, `published`, `modified`, and `references`. `VulnerabilityAssessment` exposes `technology`, `version`, `cve_count`, `high_severity`, `medium_severity`, `low_severity`, `max_score`, `cves`, and `risk_level`. `HighSeverity` counts both `HIGH` and `CRITICAL` CVEs; unrecognized severities are not counted in any severity bucket. `MaxScore` is the highest processed score, but does not determine the risk level.

Risk rules are evaluated in this order:

| `RiskLevel` | Condition |
|---|---|
| `CRITICAL` | At least one `HIGH` or `CRITICAL` CVE. |
| `HIGH` | At least three `MEDIUM` CVEs. |
| `MEDIUM` | At least one `MEDIUM` or five `LOW` CVEs. |
| `LOW` | At least one CVE, but none of the conditions above. |
| `NONE` | No CVEs returned. |

`GetThreatLevelFromAssessment` maps `NONE` to `0`, `LOW` to `2`, `MEDIUM` to `3`, `HIGH` to `4`, and `CRITICAL` to `5`; an unknown label maps to `1`. Treat the result as a limited search signal, not a confirmed vulnerability in a particular installation.

## Tests

`App/CVE/UnitTests` runs the client against a local stand-in for the NVD API
(`UnitTestKit.ServeNVD`) that answers with prepared responses in the CVE API 2.0 shape:
vulnerabilities scored under every CVSS version, low- and medium-only result sets for the risk
rules, an empty result, a truncated body and an unavailable service. No test reaches the real
NVD. The CVE identifiers in the fixtures (`CVE-2099-…`) are invented.
