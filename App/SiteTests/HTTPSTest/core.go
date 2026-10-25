// Package HTTPSTest implements the HTTPS Protocol Verification security test.
// See README.md for what it checks, how it grades and what it reports.
package HTTPSTest

import "Engine-AntiGinx/App/SiteTests"

// New creates a new security test that verifies HTTPS protocol usage.
func New() *SiteTests.ResponseTest {
	return &SiteTests.ResponseTest{
		Id:          TestId,
		Name:        TestName,
		Description: TestDescription,
		Category:    TestCategory,
		RunTest: func(params SiteTests.ResponseTestParams) SiteTests.TestResult {
			// Without the request the response answered there is no address to read the scheme
			// from; say so rather than guess
			if params.Response == nil || params.Response.Request == nil || params.Response.Request.URL == nil {
				return SiteTests.TestResult{
					Name:        TestName,
					Certainty:   detectionCertainty,
					ThreatLevel: SiteTests.Info,
					Metadata:    nil,
					Description: unknownAddressDescription,
				}
			}

			if params.Response.Request.URL.Scheme == secureScheme {
				return SiteTests.TestResult{
					Name:        TestName,
					Certainty:   detectionCertainty,
					ThreatLevel: SiteTests.None,
					Metadata:    nil,
					Description: secureConnectionDescription,
				}
			}

			return SiteTests.TestResult{
				Name:        TestName,
				Certainty:   detectionCertainty,
				ThreatLevel: SiteTests.Medium,
				Metadata:    nil,
				Description: insecureConnectionDescription,
			}
		},
	}
}
