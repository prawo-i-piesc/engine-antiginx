package UnitTests

import (
	"Engine-AntiGinx/App/SiteTests"
	"Engine-AntiGinx/App/SiteTests/UnitTestKit"
	"Engine-AntiGinx/App/SiteTests/XContentTypeOptionsTest"
	"testing"
)

func TestXContentTypeOptionsFixtures(t *testing.T) {
	cases := []struct {
		fixture   string
		level     SiteTests.ThreatLevel
		fragments []string
	}{
		{"missing_header.http", SiteTests.Low, []string{"Missing X-Content-Type-Options header"}},
		{"invalid_value.http", SiteTests.Low, []string{"invalid value 'sniff'", "should be 'nosniff'"}},
		{"nosniff.http", SiteTests.None, []string{"properly configured with 'nosniff'"}},
		{"nosniff_uppercase.http", SiteTests.None, []string{"properly configured with 'nosniff'"}},
		// Browsers act on the first comma-separated value only
		{"duplicated_nosniff.http", SiteTests.None, []string{"properly configured with 'nosniff'"}},
		{"sniff_then_nosniff.http", SiteTests.Low, []string{"invalid value 'sniff, nosniff'"}},
	}
	for _, c := range cases {
		t.Run(c.fixture, func(t *testing.T) {
			result := UnitTestKit.RunResponse(t, XContentTypeOptionsTest.New(), c.fixture)
			UnitTestKit.Expect(t, result, c.level, c.fragments...)
		})
	}
}

func TestXContentTypeOptionsMetadata(t *testing.T) {
	metadata := UnitTestKit.Metadata(t, UnitTestKit.RunResponse(t, XContentTypeOptionsTest.New(), "nosniff_uppercase.http"))
	if metadata["raw_header"] != "NOSNIFF" || metadata["parsed_value"] != "nosniff" || metadata["is_nosniff"] != true {
		t.Errorf("metadata %v does not describe the header", metadata)
	}
	metadata = UnitTestKit.Metadata(t, UnitTestKit.RunResponse(t, XContentTypeOptionsTest.New(), "duplicated_nosniff.http"))
	if metadata["raw_header"] != "nosniff, nosniff" || metadata["parsed_value"] != "nosniff" || metadata["is_nosniff"] != true {
		t.Errorf("metadata %v does not describe the repeated header", metadata)
	}
	metadata = UnitTestKit.Metadata(t, UnitTestKit.RunResponse(t, XContentTypeOptionsTest.New(), "invalid_value.http"))
	if metadata["is_nosniff"] != false {
		t.Errorf("invalid value reported as nosniff: %v", metadata)
	}
}
