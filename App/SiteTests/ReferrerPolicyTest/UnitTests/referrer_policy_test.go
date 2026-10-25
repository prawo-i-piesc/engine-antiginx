package UnitTests

import (
	"Engine-AntiGinx/App/SiteTests"
	"Engine-AntiGinx/App/SiteTests/ReferrerPolicyTest"
	"Engine-AntiGinx/App/SiteTests/UnitTestKit"
	"strings"
	"testing"
)

func TestReferrerPolicyFixtures(t *testing.T) {
	cases := []struct {
		fixture   string
		level     SiteTests.ThreatLevel
		fragments []string
	}{
		{"missing_header.http", SiteTests.Medium, []string{"Missing Referrer-Policy header", "strict-origin-when-cross-origin in current browsers"}},
		{"invalid_value.http", SiteTests.High, []string{"Invalid Referrer-Policy values detected: bogus-policy.", "No valid Referrer-Policy found", "strict-origin-when-cross-origin in current browsers"}},
		{"unsafe_url.http", SiteTests.High, []string{"'unsafe-url'", "vulnerable configuration", "WARNING"}},
		{"no_referrer_when_downgrade.http", SiteTests.Medium, []string{"'no-referrer-when-downgrade'", "weak privacy protection"}},
		{"origin_when_cross_origin.http", SiteTests.Info, []string{"'origin-when-cross-origin'", "good balance"}},
		// same-origin sends nothing to other origins at all
		{"same_origin.http", SiteTests.None, []string{"'same-origin'", "requests to other origins carry no referrer at all"}},
		{"strict_origin.http", SiteTests.None, []string{"'strict-origin'", "strong privacy protection"}},
		{"strict_origin_when_cross_origin.http", SiteTests.None, []string{"'strict-origin-when-cross-origin'", "W3C recommended"}},
		{"no_referrer.http", SiteTests.None, []string{"'no-referrer'", "excellent privacy protection"}},
		// The browser applies the last policy it understands
		{"fallback_list.http", SiteTests.None, []string{"configured with 'strict-origin-when-cross-origin' (no-referrer, strict-origin-when-cross-origin)"}},
		{"valid_with_unknown_token.http", SiteTests.None, []string{"Invalid Referrer-Policy values detected: bogus-policy.", "configured with 'no-referrer'"}},
	}
	for _, c := range cases {
		t.Run(c.fixture, func(t *testing.T) {
			result := UnitTestKit.RunResponse(t, ReferrerPolicyTest.New(), c.fixture)
			UnitTestKit.Expect(t, result, c.level, c.fragments...)
		})
	}
}

func TestReferrerPolicyNoLongerCallsTheOldDefaultTheDefault(t *testing.T) {
	for _, fixture := range []string{"missing_header.http", "invalid_value.http", "no_referrer_when_downgrade.http"} {
		result := UnitTestKit.RunResponse(t, ReferrerPolicyTest.New(), fixture)
		if strings.Contains(result.Description, "typically no-referrer-when-downgrade") || strings.Contains(result.Description, "(browser default)") {
			t.Errorf("%s: description %q names no-referrer-when-downgrade as the browser default", fixture, result.Description)
		}
	}
}

func TestReferrerPolicyMetadata(t *testing.T) {
	metadata := UnitTestKit.Metadata(t, UnitTestKit.RunResponse(t, ReferrerPolicyTest.New(), "fallback_list.http"))
	policies, _ := metadata["policies"].([]any)
	if len(policies) != 2 || policies[0] != "no-referrer" || policies[1] != "strict-origin-when-cross-origin" {
		t.Errorf("policies %v", metadata["policies"])
	}
	if metadata["effective_policy"] != "strict-origin-when-cross-origin" || metadata["policy_count"] != float64(2) || metadata["has_unsafe"] != false {
		t.Errorf("metadata %v does not describe the fallback list", metadata)
	}

	metadata = UnitTestKit.Metadata(t, UnitTestKit.RunResponse(t, ReferrerPolicyTest.New(), "unsafe_url.http"))
	if metadata["has_unsafe"] != true || metadata["effective_policy"] != "unsafe-url" {
		t.Errorf("metadata %v does not flag unsafe-url", metadata)
	}

	metadata = UnitTestKit.Metadata(t, UnitTestKit.RunResponse(t, ReferrerPolicyTest.New(), "valid_with_unknown_token.http"))
	invalid, _ := metadata["invalid_policies"].([]any)
	if len(invalid) != 1 || invalid[0] != "bogus-policy" {
		t.Errorf("invalid policies %q, want the trimmed token", metadata["invalid_policies"])
	}
}
