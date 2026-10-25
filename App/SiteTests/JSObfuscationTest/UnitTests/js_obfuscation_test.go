package UnitTests

import (
	"Engine-AntiGinx/App/SiteTests"
	"Engine-AntiGinx/App/SiteTests/JSObfuscationTest"
	"Engine-AntiGinx/App/SiteTests/UnitTestKit"
	"testing"
)

func TestJSObfuscationFixtures(t *testing.T) {
	cases := []struct {
		fixture   string
		level     SiteTests.ThreatLevel
		fragments []string
	}{
		{"json_api_response.http", SiteTests.None, []string{"No JavaScript content detected"}},
		{"html_without_scripts.http", SiteTests.None, []string{"No JavaScript obfuscation detected"}},
		{"clean_inline_script.http", SiteTests.None, []string{"No JavaScript obfuscation detected"}},
		// A single decoded configuration blob is minimal, below what counts as obfuscation
		{"base64_config_blob.http", SiteTests.Info, []string{"No JavaScript obfuscation detected"}},
		{"hex_escape_run.http", SiteTests.Low, []string{"light obfuscation (score: 23/100)", "No malicious indicators", "Hex escape sequences"}},
		// A score of exactly 20 is where obfuscation starts, for the flag, the level and the grade
		{"unicode_escape_score_twenty.http", SiteTests.Low, []string{"JavaScript obfuscation detected: light obfuscation (score: 20/100)"}},
		{"unicode_escape_run.http", SiteTests.Low, []string{"light obfuscation (score: 25/100)", "Unicode escape sequences", "Base64 encoded strings"}},
		{"string_array_rotation.http", SiteTests.Low, []string{"Hexadecimal number arrays detected"}},
		// Heavy obfuscation without a malicious indicator is still only Low
		{"heavy_obfuscation_no_indicators.http", SiteTests.Low, []string{"heavy obfuscation (score: 66/100)", "No malicious indicators"}},
		// Obfuscation alone stays Low however heavy; one malicious indicator is Medium and two or
		// more independent ones are High, whatever the score
		{"packed_eval_payload.http", SiteTests.Medium, []string{"MALICIOUS INDICATORS", "Suspicious keyword 'payload'"}},
		{"xor_self_decrypting_loader.http", SiteTests.Medium, []string{"moderate obfuscation (score: 59/100)", "Possible self-decrypting code detected"}},
		{"document_write_decoded.http", SiteTests.High, []string{"MALICIOUS INDICATORS: Self-modifying code: document.write with decoded content; String passed to setTimeout/setInterval", "Large character code arrays"}},
		{"eval_atob_chain.http", SiteTests.High, []string{"extreme obfuscation (score: 100/100)", "eval() called with encoded/decoded input", "Multiple layers of encoding"}},
		// A JavaScript file is analysed as one script, without <script> elements around it
		{"obfuscated_javascript_file.http", SiteTests.High, []string{"extreme obfuscation (score: 100/100)", "eval() called with encoded/decoded input"}},
	}
	for _, c := range cases {
		t.Run(c.fixture, func(t *testing.T) {
			result := UnitTestKit.RunResponse(t, JSObfuscationTest.New(), c.fixture)
			UnitTestKit.Expect(t, result, c.level, c.fragments...)
		})
	}
}

func TestJSObfuscationMetadata(t *testing.T) {
	metadata := UnitTestKit.Metadata(t, UnitTestKit.RunResponse(t, JSObfuscationTest.New(), "eval_atob_chain.http"))
	if metadata["hasObfuscation"] != true || metadata["obfuscationScore"] != float64(100) || metadata["obfuscationLevel"] != "extreme" {
		t.Errorf("metadata %v does not describe extreme obfuscation", metadata)
	}
	if metadata["encodedStrings"] != float64(2) {
		t.Errorf("encodedStrings %v, want the two atob calls", metadata["encodedStrings"])
	}
	if indicators, _ := metadata["maliciousIndicators"].([]any); len(indicators) != 2 {
		t.Errorf("maliciousIndicators %v, want two", metadata["maliciousIndicators"])
	}

	metadata = UnitTestKit.Metadata(t, UnitTestKit.RunResponse(t, JSObfuscationTest.New(), "clean_inline_script.http"))
	if metadata["hasObfuscation"] != false || metadata["obfuscationScore"] != float64(0) {
		t.Errorf("clean script reported as %v", metadata)
	}

	metadata = UnitTestKit.Metadata(t, UnitTestKit.RunResponse(t, JSObfuscationTest.New(), "unicode_escape_score_twenty.http"))
	if metadata["hasObfuscation"] != true || metadata["obfuscationScore"] != float64(20) || metadata["obfuscationLevel"] != "light" {
		t.Errorf("score 20 reported as %v, want obfuscated at the light level", metadata)
	}

	// A response without JavaScript carries no analysis at all
	result := UnitTestKit.RunResponse(t, JSObfuscationTest.New(), "json_api_response.http")
	if result.Metadata != nil {
		t.Errorf("non-HTML response carries metadata %v", result.Metadata)
	}
}
