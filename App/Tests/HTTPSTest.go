package Tests

// NewHTTPSTest creates a new test to check if communication uses HTTPS protocol
func NewHTTPSTest() *ResponseTest {
	return &ResponseTest{
		Id:          "https-protocol-check",
		Name:        "HTTPS Protocol Verification",
		Description: "Verifies if the website communication is secured with HTTPS protocol",
		RunTest: func(params ResponseTestParams) TestResult {

			if params.Response.Request.URL.Scheme == "https" {
				return TestResult{
					Name:        "HTTPS Protocol Verification",
					Certainty:   100,
					ThreatLevel: None,
					Metadata:    nil,
					Description: "Connection is secured with HTTPS protocol - data transmission is encrypted",
				}
			}

			return TestResult{
				Name:        "HTTPS Protocol Verification",
				Certainty:   100,
				ThreatLevel: High,
				Metadata:    nil,
				Description: "Connection uses insecure HTTP protocol - data is transmitted in plaintext and vulnerable to interception",
			}
		},
	}
}
