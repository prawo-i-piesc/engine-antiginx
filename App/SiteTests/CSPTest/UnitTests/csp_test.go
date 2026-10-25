package UnitTests

import (
	"Engine-AntiGinx/App/SiteTests"
	"Engine-AntiGinx/App/SiteTests/CSPTest"
	"Engine-AntiGinx/App/SiteTests/UnitTestKit"
	"strings"
	"testing"
)

func TestCSPFixtures(t *testing.T) {
	cases := []struct {
		fixture   string
		level     SiteTests.ThreatLevel
		fragments []string
	}{
		{"missing_header.http", SiteTests.Critical, []string{"Missing Content-Security-Policy header"}},
		// A critical issue puts the policy in the poor band whatever else it restricts
		{"unsafe_inline_script.http", SiteTests.High, []string{"poor protection level (strength: 19/100)", "CRITICAL ISSUES: script-src unsafe-inline allows any inline scripts"}},
		{"unsafe_eval_script.http", SiteTests.High, []string{"poor protection level (strength: 19/100)", "unsafe-eval permits eval() and Function() constructors", "script-src allows unsafe-eval"}},
		{"wildcard_default_src.http", SiteTests.High, []string{"poor protection level (strength: 5/100)", "default-src wildcard undermines security policy"}},
		// Without script-src, scripts take their sources from default-src
		{"unsafe_inline_default_fallback.http", SiteTests.High, []string{"poor protection level", "script-src inherits unsafe-inline from default-src", "default-src allows unsafe-inline"}},
		{"no_fetch_directives.http", SiteTests.High, []string{"poor protection level (strength: 10/100)", "Missing 8 recommended directives"}},
		{"default_src_only.http", SiteTests.Medium, []string{"weak protection level (strength: 20/100)", "Missing 7 recommended directives: base-uri, form-action, frame-ancestors, img-src, object-src, script-src, style-src."}},
		{"partial_policy.http", SiteTests.Low, []string{"acceptable protection level (strength: 40/100)", "Missing 5 recommended directives: base-uri, form-action, frame-ancestors, img-src, style-src."}},
		{"self_policy.http", SiteTests.Info, []string{"good protection level (strength: 70/100)", "Missing 3 recommended directives: base-uri, form-action, img-src.", "Recommendations: Add base-uri directive"}},
		// A wildcard outside the critical directives costs points but is not a critical issue
		{"wildcard_images.http", SiteTests.Info, []string{"good protection level (strength: 65/100)", "img-src allows wildcard (*), permitting any source"}},
		// script-src and style-src set their own sources, so the unsafe default reaches only
		// directives that cannot run script
		{"default_src_unsafe_inline_overridden.http", SiteTests.Info, []string{"good protection level (strength: 65/100)", "default-src allows unsafe-inline"}},
		{"strict_nonce_policy.http", SiteTests.None, []string{"excellent protection level (strength: 95/100)"}},
	}
	for _, c := range cases {
		t.Run(c.fixture, func(t *testing.T) {
			result := UnitTestKit.RunResponse(t, CSPTest.New(), c.fixture)
			UnitTestKit.Expect(t, result, c.level, c.fragments...)
		})
	}
}

func TestCSPOverriddenDefaultIsNotCritical(t *testing.T) {
	result := UnitTestKit.RunResponse(t, CSPTest.New(), "default_src_unsafe_inline_overridden.http")
	if strings.Contains(result.Description, "CRITICAL") {
		t.Errorf("unsafe default overridden by script-src reported as critical: %s", result.Description)
	}
}

// The policy is a map, so the order of findings must come from sorting, not iteration.
func TestCSPOutputIsDeterministic(t *testing.T) {
	for _, fixture := range []string{"default_src_only.http", "unsafe_inline_default_fallback.http", "no_fetch_directives.http"} {
		first := UnitTestKit.RunResponse(t, CSPTest.New(), fixture)
		for range 20 {
			if again := UnitTestKit.RunResponse(t, CSPTest.New(), fixture); again.Description != first.Description {
				t.Fatalf("%s: description changed between runs:\n%s\n%s", fixture, first.Description, again.Description)
			}
		}
	}
}

func TestCSPMetadata(t *testing.T) {
	metadata := UnitTestKit.Metadata(t, UnitTestKit.RunResponse(t, CSPTest.New(), "self_policy.http"))
	if metadata["policyStrength"] != float64(70) || metadata["protectionLevel"] != "good" {
		t.Errorf("strength %v, level %v, want 70 and good", metadata["policyStrength"], metadata["protectionLevel"])
	}
	compliance, _ := metadata["directiveCompliance"].(map[string]any)
	if compliance["object-src"] != "excellent" || compliance["script-src"] != "fair" {
		t.Errorf("directive compliance %v", compliance)
	}
	missing, _ := metadata["missingDirectives"].([]any)
	if len(missing) != 3 || missing[0] != "base-uri" || missing[1] != "form-action" || missing[2] != "img-src" {
		t.Errorf("missing directives %v, want base-uri, form-action, img-src", metadata["missingDirectives"])
	}
	actions, _ := metadata["recommendedActions"].([]any)
	if len(actions) != 3 || !strings.HasPrefix(actions[0].(string), "Add base-uri directive") {
		t.Errorf("recommended actions %v", metadata["recommendedActions"])
	}
}

func TestCSPMetadataListsUnsafeValues(t *testing.T) {
	metadata := UnitTestKit.Metadata(t, UnitTestKit.RunResponse(t, CSPTest.New(), "unsafe_inline_script.http"))
	unsafe, _ := metadata["unsafeDirectives"].([]any)
	if len(unsafe) != 1 || unsafe[0] != "script-src: 'unsafe-inline'" {
		t.Errorf("unsafe directives %v", metadata["unsafeDirectives"])
	}
	if missing, _ := metadata["missingDirectives"].([]any); len(missing) != 0 {
		t.Errorf("complete policy reported missing directives %v", missing)
	}
	if metadata["protectionLevel"] != "poor" || metadata["policyStrength"] != float64(19) {
		t.Errorf("level %v, strength %v, want poor and 19", metadata["protectionLevel"], metadata["policyStrength"])
	}

	metadata = UnitTestKit.Metadata(t, UnitTestKit.RunResponse(t, CSPTest.New(), "unsafe_inline_default_fallback.http"))
	critical, _ := metadata["criticalVulns"].([]any)
	if len(critical) != 1 || critical[0] != "script-src inherits unsafe-inline from default-src, allowing any inline scripts" {
		t.Errorf("critical vulnerabilities %v", metadata["criticalVulns"])
	}
}
