package modules

import (
	"Engine-AntiGinx/App/CVE"
	"Engine-AntiGinx/App/SiteTests"
)

// MapCVEThreat maps CVE vulnerability assessment results from the NIST NVD database to the
// Engine-AntiGinx ThreatLevel enumeration.
func MapCVEThreat(assessment CVE.VulnerabilityAssessment) SiteTests.ThreatLevel {
	// High severity vulnerabilities take precedence
	if assessment.HighSeverity > 0 {
		return SiteTests.Critical
	}

	// Medium vulnerabilities assessment
	if assessment.MediumSeverity > 5 {
		return SiteTests.High
	} else if assessment.MediumSeverity > 0 {
		return SiteTests.Medium
	}

	// Low vulnerabilities in high quantity
	if assessment.LowSeverity > 10 {
		return SiteTests.Medium
	} else if assessment.LowSeverity > 0 {
		return SiteTests.Low
	}

	// Any CVE presence indicates some risk
	if assessment.CVECount > 0 {
		return SiteTests.Info
	}

	return SiteTests.None
}
