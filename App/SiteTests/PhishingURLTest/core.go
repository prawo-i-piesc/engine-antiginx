// Package PhishingURLTest implements the Phishing URL Analysis security test.
// See README.md for what it checks, how it grades and what it reports.
package PhishingURLTest

import (
	"Engine-AntiGinx/App/SiteTests"
	"Engine-AntiGinx/App/SiteTests/PhishingURLTest/modules"
	"fmt"
	"strings"
)

// The analysis stages live in the modules package and own no data of their own: the datasets
// in data.go and the limits in config.go are wired into them here, so that changing what the
// engine looks for never means editing how it looks.
var (
	domainAnalyzer = modules.DomainAnalyzer{
		Popular:            popularDomainDatabase,
		LetterReplacements: popularLetterReplacementDatabase,
		Confusables:        confusableRuneDatabase,
	}

	parameterAnalyzer = modules.ParameterAnalyzer{
		Credential:            credentialParameterDatabase,
		Sensitive:             sensitiveParameterDatabase,
		Identity:              identityParameterDatabase,
		Redirect:              redirectParameterDatabase,
		DangerousSchemes:      dangerousSchemeDatabase,
		PathKeywords:          phishingPathKeywordDatabase,
		Brands:                brandNames(),
		MaxQueryLength:        maxReasonableQueryLength,
		MaxParameterCount:     maxReasonableParameterCount,
		MinBrandKeywordLength: minBrandKeywordLength,
		RedactedPlaceholder:   redactedPlaceholder,
	}
)

// brandNames lists the brands the popular domain dataset is grouped by, which is what the
// parameter analysis matches against when a brand is claimed outside the hostname.
func brandNames() []string {
	names := make([]string, 0, len(popularDomainDatabase))
	for brand := range popularDomainDatabase {
		names = append(names, brand)
	}
	return names
}

// New creates and returns a new PreResponseTest instance for phishing detection.
func New() *SiteTests.PreResponseTest {
	return &SiteTests.PreResponseTest{
		Id:          TestId,
		Name:        TestName,
		Description: TestDescription,
		Category:    TestCategory,
		RunTest: func(params SiteTests.PreResponseTestParams) SiteTests.TestResult {
			target := params.Target
			if target == nil {
				return SiteTests.TestResult{
					Name:        TestName,
					Certainty:   100,
					ThreatLevel: SiteTests.Info,
					Metadata: map[string]any{
						"url":  "",
						"host": "",
					},
					Description: "Target URL is unavailable, phishing analysis could not be performed",
				}
			}

			host := strings.ToLower(strings.TrimSuffix(target.Hostname(), "."))
			domainAnalysis := domainAnalyzer.Analyze(host)
			parameterAnalysis := parameterAnalyzer.Analyze(target)

			domainThreat := modules.EvaluateDomainThreat(domainAnalysis)
			parameterThreat := modules.EvaluateParameterThreat(parameterAnalysis)

			return SiteTests.TestResult{
				Name:        TestName,
				Certainty:   evaluatePhishingCertainty(domainAnalysis, parameterAnalysis),
				ThreatLevel: combinePhishingThreatLevels(domainThreat, parameterThreat),
				Metadata:    combinePhishingAnalyses(host, domainAnalysis, parameterAnalysis),
				Description: generateCombinedPhishingDescription(domainAnalysis, parameterAnalysis),
			}
		},
	}
}

// combinePhishingThreatLevels merges the classifications of both analysis dimensions into the
// threat level reported by the test.
func combinePhishingThreatLevels(domainThreat SiteTests.ThreatLevel, parameterThreat SiteTests.ThreatLevel) SiteTests.ThreatLevel {
	combined := SiteTests.HighestThreatLevel(domainThreat, parameterThreat)
	if domainThreat >= SiteTests.Medium && parameterThreat >= SiteTests.Medium {
		combined = SiteTests.EscalateThreatLevel(combined)
	}
	return combined
}

// evaluatePhishingCertainty determines the confidence reported for the combined result.
func evaluatePhishingCertainty(domainAnalysis map[string]any, parameterAnalysis map[string]any) int {
	domainSuspicious, _ := domainAnalysis["is_suspicious"].(bool)
	parameterSuspicious, _ := parameterAnalysis["is_suspicious"].(bool)

	if !domainSuspicious && !parameterSuspicious {
		return 100
	}

	if parameterSuspicious {
		embedded, _ := parameterAnalysis["embedded_credentials"].(bool)
		credentials, _ := parameterAnalysis["credential_parameters"].([]string)
		if !embedded && len(credentials) == 0 {
			return 85
		}
	}

	return 95
}

// combinePhishingAnalyses merges the metadata of both analysis dimensions into the single map
// reported by the test.
func combinePhishingAnalyses(host string, domainAnalysis map[string]any, parameterAnalysis map[string]any) map[string]any {
	domainSuspicious, _ := domainAnalysis["is_suspicious"].(bool)
	parameterSuspicious, _ := parameterAnalysis["is_suspicious"].(bool)
	domainPatterns, _ := domainAnalysis["detected_patterns"].([]string)
	parameterPatterns, _ := parameterAnalysis["detected_patterns"].([]string)

	patterns := make([]string, 0, len(domainPatterns)+len(parameterPatterns))
	patterns = append(patterns, domainPatterns...)
	patterns = append(patterns, parameterPatterns...)

	return map[string]any{
		"url":                parameterAnalysis["url"],
		"host":               host,
		"is_suspicious":      domainSuspicious || parameterSuspicious,
		"detected_patterns":  patterns,
		"domain_analysis":    domainAnalysis,
		"parameter_analysis": parameterAnalysis,
	}
}

// generateCombinedPhishingDescription joins the descriptions of both analysis dimensions into
// the single human-readable summary reported by the test, so a reader always learns what the
// hostname and the parameters each contributed.
func generateCombinedPhishingDescription(domainAnalysis map[string]any, parameterAnalysis map[string]any) string {
	return fmt.Sprintf(
		"Hostname: %s. URL parameters: %s",
		modules.DescribeDomain(domainAnalysis),
		modules.DescribeParameters(parameterAnalysis),
	)
}
