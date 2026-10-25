// Package URLhausTest implements the URLhaus Malicious URL Lookup security test.
// See README.md for what it checks, how it grades and what it reports.
package URLhausTest

import (
	"Engine-AntiGinx/App/SiteTests"
	"Engine-AntiGinx/App/SiteTests/URLhausTest/modules"
	"net/http"
	"os"
	"strings"
)

// newLookup wires the environment, the limits in config.go and the listings in data.go into
// the lookup stage.
func newLookup() modules.Lookup {
	baseURL := defaultBaseURL
	if configured := strings.TrimSpace(os.Getenv(baseURLEnvVar)); configured != "" {
		baseURL = strings.TrimSuffix(configured, "/")
	}
	return modules.Lookup{
		HTTPClient:       &http.Client{Timeout: lookupTimeout},
		BaseURL:          baseURL,
		AuthKey:          strings.TrimSpace(os.Getenv(authKeyEnvVar)),
		MaxResponseSize:  maxResponseSize,
		MaxReportedURLs:  maxReportedURLs,
		AbusedLegitimate: abusedLegitimateListings,
		Malicious:        maliciousListings,
	}
}

// New creates a new PreResponseTest that looks the target up in URLhaus.
func New() *SiteTests.PreResponseTest {
	return &SiteTests.PreResponseTest{
		Id:          TestId,
		Name:        TestName,
		Description: TestDescription,
		Category:    TestCategory,
		RunTest: func(params SiteTests.PreResponseTestParams) SiteTests.TestResult {
			lookup := newLookup()
			if lookup.AuthKey == "" {
				return SiteTests.TestResult{
					Name:        TestName,
					Certainty:   lookupUnavailableCertainty,
					ThreatLevel: SiteTests.Info,
					Metadata:    modules.URLhausMetadata{LookupError: "auth key not configured"},
					Description: "URLhaus was not consulted: no abuse.ch Auth-Key is configured in " + authKeyEnvVar + ".",
				}
			}

			metadata := lookup.Check(params.Target)
			if !metadata.Checked {
				return SiteTests.TestResult{
					Name:        TestName,
					Certainty:   lookupUnavailableCertainty,
					ThreatLevel: SiteTests.Info,
					Metadata:    metadata,
					Description: modules.Describe(metadata),
				}
			}

			return SiteTests.TestResult{
				Name:        TestName,
				Certainty:   certainty(metadata),
				ThreatLevel: modules.EvaluateThreat(metadata),
				Metadata:    metadata,
				Description: modules.Describe(metadata),
			}
		},
	}
}

// certainty reports how much confidence the verdict deserves.
func certainty(metadata modules.URLhausMetadata) int {
	switch {
	case metadata.URLListed:
		return listedURLCertainty
	case metadata.HostListed && metadata.AbusedLegitimate:
		return abusedServiceCertainty
	case metadata.HostListed:
		return listedHostCertainty
	default:
		return cleanCertainty
	}
}
