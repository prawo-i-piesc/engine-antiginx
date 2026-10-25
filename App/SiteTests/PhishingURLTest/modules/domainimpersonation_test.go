package modules

import "testing"

// A hostname one typo away from two brands' domains must always be reported against the
// same brand, not whichever one map iteration reaches first.
func TestAmbiguousLookalikePicksBrandsInOrder(t *testing.T) {
	analyzer := DomainAnalyzer{Popular: map[string][]string{
		"zeta":  {"abc.com"},
		"alpha": {"abd.com"},
		"mid":   {"abf.com"},
	}}
	for range 50 {
		analysis := analyzer.Analyze("abe.com")
		if analysis.MatchedBrand != "alpha" || analysis.MatchedLegitimateDomain != "abd.com" {
			t.Fatalf("abe.com matched %s (%s), want alpha (abd.com)", analysis.MatchedBrand, analysis.MatchedLegitimateDomain)
		}
	}
}

func TestKnownDomainIsLegitimate(t *testing.T) {
	analysis := DomainAnalyzer{Popular: map[string][]string{"alpha": {"abd.com"}}}.Analyze("abd.com")
	if !analysis.IsKnownLegitimate || analysis.IsSuspicious || EvaluateDomainThreat(analysis) != 0 {
		t.Errorf("own domain analysed as %+v", analysis)
	}
}
