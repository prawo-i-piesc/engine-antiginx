package SiteTests

// HeaderTest is the shape shared by tests that grade one response header: a fixed verdict
// when the header is absent, and analyze → evaluate → describe when it is present. M is the
// test's own analysis type, reported as the result's metadata.
type HeaderTest[M any] struct {
	Name               string               // Test name carried in every result
	Header             string               // Response header the test grades
	MissingLevel       ThreatLevel          // Verdict when the header is absent
	MissingDescription string               // Explanation when the header is absent
	Certainty          int                  // Certainty when the header is present
	Analyze            func(value string) M // Parses the header value
	Evaluate           func(M) ThreatLevel  // Grades the analysis
	Describe           func(M) string       // Explains the analysis
}

// Run grades the header of the response. An absent header is a fact rather than an
// inference, so it is reported with full certainty and no metadata.
func (h HeaderTest[M]) Run(params ResponseTestParams) TestResult {
	value := params.Response.Header.Get(h.Header)
	if value == "" {
		return TestResult{
			Name:        h.Name,
			Certainty:   100,
			ThreatLevel: h.MissingLevel,
			Metadata:    nil,
			Description: h.MissingDescription,
		}
	}

	analysis := h.Analyze(value)
	return TestResult{
		Name:        h.Name,
		Certainty:   h.Certainty,
		ThreatLevel: h.Evaluate(analysis),
		Metadata:    analysis,
		Description: h.Describe(analysis),
	}
}
