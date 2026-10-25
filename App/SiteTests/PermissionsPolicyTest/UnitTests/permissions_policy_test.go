package UnitTests

import (
	"Engine-AntiGinx/App/SiteTests"
	"Engine-AntiGinx/App/SiteTests/PermissionsPolicyTest"
	"Engine-AntiGinx/App/SiteTests/UnitTestKit"
	"strings"
	"testing"
)

func TestPermissionsPolicyFixtures(t *testing.T) {
	cases := []struct {
		fixture   string
		level     SiteTests.ThreatLevel
		fragments []string
	}{
		{"missing_header.http", SiteTests.High, []string{"Missing Permissions-Policy header"}},
		// Feature-Policy syntax is not a Permissions-Policy, so browsers ignore the header
		{"legacy_feature_policy_syntax.http", SiteTests.High, []string{"contains no valid directives"}},
		{"three_dangerous_open.http", SiteTests.High, []string{"WARNING: Allows dangerous features: camera, microphone, geolocation", "Uses wildcards for features: camera"}},
		{"one_dangerous_open.http", SiteTests.Medium, []string{"5 directives", "Properly restricts features: camera, microphone, payment, usb", "Allows dangerous features: geolocation"}},
		{"wildcard_fullscreen.http", SiteTests.Medium, []string{"Allows suspicious features: fullscreen", "Uses wildcards for features: fullscreen"}},
		{"two_suspicious_open.http", SiteTests.Low, []string{"Allows suspicious features: autoplay, fullscreen"}},
		{"single_directive.http", SiteTests.Low, []string{"1 directives", "Properly restricts features: camera", "Minimal policy"}},
		{"one_suspicious_open.http", SiteTests.Info, []string{"Allows suspicious features: fullscreen", "Good security configuration"}},
		// The empty part after the trailing comma is not a directive
		{"trailing_comma.http", SiteTests.Info, []string{"4 directives", "Properly restricts features: camera, microphone, geolocation, payment", "Good security configuration"}},
		{"comprehensive.http", SiteTests.None, []string{"6 directives", "Properly restricts features: camera, microphone, geolocation, payment, usb, fullscreen", "Excellent security configuration"}},
	}
	for _, c := range cases {
		t.Run(c.fixture, func(t *testing.T) {
			result := UnitTestKit.RunResponse(t, PermissionsPolicyTest.New(), c.fixture)
			UnitTestKit.Expect(t, result, c.level, c.fragments...)
		})
	}
}

// The closing verdict follows the grade: only a None is excellent, only an Info is good.
func TestPermissionsPolicyVerdictMatchesGrade(t *testing.T) {
	for _, fixture := range []string{"single_directive.http", "two_suspicious_open.http", "one_dangerous_open.http", "wildcard_fullscreen.http", "three_dangerous_open.http"} {
		result := UnitTestKit.RunResponse(t, PermissionsPolicyTest.New(), fixture)
		if strings.Contains(result.Description, "Excellent security configuration") || strings.Contains(result.Description, "Good security configuration") {
			t.Errorf("%s graded %v but described as %q", fixture, result.ThreatLevel, result.Description)
		}
	}
}

func TestPermissionsPolicyMetadata(t *testing.T) {
	metadata := UnitTestKit.Metadata(t, UnitTestKit.RunResponse(t, PermissionsPolicyTest.New(), "three_dangerous_open.http"))
	dangerous, _ := metadata["dangerous_allowed"].([]any)
	if len(dangerous) != 3 || dangerous[0] != "camera" || dangerous[1] != "microphone" || dangerous[2] != "geolocation" {
		t.Errorf("dangerous features %v", metadata["dangerous_allowed"])
	}
	wildcards, _ := metadata["wildcard_features"].([]any)
	if len(wildcards) != 1 || wildcards[0] != "camera" || metadata["total_directives"] != float64(3) {
		t.Errorf("metadata %v does not describe the header", metadata)
	}

	metadata = UnitTestKit.Metadata(t, UnitTestKit.RunResponse(t, PermissionsPolicyTest.New(), "trailing_comma.http"))
	if metadata["total_directives"] != float64(4) {
		t.Errorf("total directives %v, want 4", metadata["total_directives"])
	}

	metadata = UnitTestKit.Metadata(t, UnitTestKit.RunResponse(t, PermissionsPolicyTest.New(), "legacy_feature_policy_syntax.http"))
	if metadata["total_directives"] != float64(0) || metadata["restricted_features"] != nil {
		t.Errorf("legacy syntax reported as %v", metadata)
	}
}
