package modules

import (
	"Engine-AntiGinx/App/CVE"
	"Engine-AntiGinx/App/SiteTests"
)

// MapCVEThreat turns the risk level of a CVE assessment — the CVSS rating of the most severe
// CVE affecting a release — into a threat level, band for band: Critical, High, Medium and Low
// are the CVSS qualitative ratings of the same names. A CVE NVD has not scored yet is known but
// unrated, which is Info; no CVE, or one scored 0.0, is None. The number of CVEs does not raise
// the level — CVSS rates each vulnerability on its own and defines no way to add several up.
func MapCVEThreat(riskLevel string) SiteTests.ThreatLevel {
	switch riskLevel {
	case CVE.SeverityCritical:
		return SiteTests.Critical
	case CVE.SeverityHigh:
		return SiteTests.High
	case CVE.SeverityMedium:
		return SiteTests.Medium
	case CVE.SeverityLow:
		return SiteTests.Low
	case CVE.RiskUnscored:
		return SiteTests.Info
	default:
		return SiteTests.None
	}
}

// DisclosureThreat grades what the headers give away when no known vulnerability applies:
// information exposure (CWE-200) that helps an attacker choose an exploit but is not one.
// A disclosed release number is at least Low, since it is what an attacker looks up.
func DisclosureThreat(exposedHeaders int, releaseDisclosed bool, lowFrom int, mediumFrom int) SiteTests.ThreatLevel {
	level := SiteTests.None
	switch {
	case exposedHeaders >= mediumFrom:
		level = SiteTests.Medium
	case exposedHeaders >= lowFrom:
		level = SiteTests.Low
	case exposedHeaders > 0:
		level = SiteTests.Info
	}
	if releaseDisclosed {
		level = SiteTests.HighestThreatLevel(level, SiteTests.Low)
	}
	return level
}
