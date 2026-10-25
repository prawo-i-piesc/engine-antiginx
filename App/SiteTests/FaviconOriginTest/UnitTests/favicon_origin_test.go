package UnitTests

import (
	"Engine-AntiGinx/App/SiteTests"
	"Engine-AntiGinx/App/SiteTests/FaviconOriginTest"
	"Engine-AntiGinx/App/SiteTests/UnitTestKit"
	"strings"
	"testing"
)

func TestFaviconOriginFixtures(t *testing.T) {
	cases := []struct {
		fixture   string
		level     SiteTests.ThreatLevel
		fragments []string
	}{
		{"no_icon_declared.http", SiteTests.None, []string{"declares no icon"}},
		{"same_host_icons.http", SiteTests.None, []string{"All 2 declared icon(s) are loaded from the page's own site"}},
		{"same_site_static_host.http", SiteTests.None, []string{"All 2 declared icon(s)", "embedded in the page"}},
		{"same_organisation_brand.http", SiteTests.None, []string{"All 1 declared icon(s)"}},
		{"commented_out_brand_icon.http", SiteTests.None, []string{"All 1 declared icon(s)"}},
		// An href no browser fetches is reported as such, not as an icon from the page's own site
		{"unresolvable_icon_href.http", SiteTests.None, []string{`2 icon declaration(s) ("javascript:void(0)", "http://[::1") do not resolve to an http or https address`}},
		{"unresolvable_and_own_icon.http", SiteTests.None, []string{"1 declared icon(s) are loaded from the page's own site", `1 icon declaration(s) ("javascript:void(0)") do not resolve`}},
		// Two GitHub Pages sites belong to unrelated owners, so the sibling is not the page's own site
		{"github_pages_sibling_icon.http", SiteTests.Info, []string{"some-other-project.github.io (GitHub Pages)"}},
		{"cdn_asset_host.http", SiteTests.Info, []string{"cdn.shopify.com (Shopify)", "content delivery network"}},
		{"unrelated_domain_icon.http", SiteTests.Info, []string{"www.bakery-original.de, a domain unrelated to example.com"}},
		{"base_href_foreign.http", SiteTests.Info, []string{"original-site.org, a domain unrelated to example.com"}},
		{"ip_address_icon.http", SiteTests.Low, []string{"bare address 203.0.113.7"}},
		{"brand_impersonation_paypal.http", SiteTests.Low, []string{"www.paypalobjects.com, a domain of paypal, while being served from secure-account-verify.com", "a domain unrelated to secure-account-verify.com"}},
	}
	for _, c := range cases {
		t.Run(c.fixture, func(t *testing.T) {
			result := UnitTestKit.RunResponse(t, FaviconOriginTest.New(), c.fixture)
			UnitTestKit.Expect(t, result, c.level, c.fragments...)
		})
	}
}

func TestFaviconBrandImpersonationMetadata(t *testing.T) {
	result := UnitTestKit.RunResponse(t, FaviconOriginTest.New(), "brand_impersonation_paypal.http")
	if result.Certainty != 85 {
		t.Errorf("certainty %d, want 85 for a brand finding", result.Certainty)
	}
	metadata := UnitTestKit.Metadata(t, result)
	if metadata["PageDomain"] != "secure-account-verify.com" {
		t.Errorf("PageDomain %v", metadata["PageDomain"])
	}
	brands, _ := metadata["ImpersonatedBrands"].([]any)
	if len(brands) != 1 || brands[0] != "paypal" {
		t.Errorf("ImpersonatedBrands %v, want [paypal] once for two paypal icons", metadata["ImpersonatedBrands"])
	}
	icons, _ := metadata["Icons"].([]any)
	origins := []string{}
	for _, icon := range icons {
		origin, _ := icon.(map[string]any)["Origin"].(string)
		origins = append(origins, origin)
	}
	want := []string{"brand", "brand", "foreign"}
	if len(origins) != len(want) || origins[0] != want[0] || origins[1] != want[1] || origins[2] != want[2] {
		t.Errorf("icon origins %v, want %v in document order", origins, want)
	}
}

func TestFaviconBaseHrefResolution(t *testing.T) {
	metadata := UnitTestKit.Metadata(t, UnitTestKit.RunResponse(t, FaviconOriginTest.New(), "base_href_foreign.http"))
	icons, _ := metadata["Icons"].([]any)
	if len(icons) != 1 {
		t.Fatalf("icons %v, want one", metadata["Icons"])
	}
	icon := icons[0].(map[string]any)
	if icon["URL"] != "https://original-site.org/assets/favicon.png" || icon["Href"] != "favicon.png" {
		t.Errorf("icon %v not resolved against <base href>", icon)
	}
}

func TestFaviconSameOrganisationMetadata(t *testing.T) {
	metadata := UnitTestKit.Metadata(t, UnitTestKit.RunResponse(t, FaviconOriginTest.New(), "same_organisation_brand.http"))
	icons, _ := metadata["Icons"].([]any)
	if len(icons) != 1 {
		t.Fatalf("icons %v, want one", metadata["Icons"])
	}
	icon := icons[0].(map[string]any)
	if icon["Origin"] != "same-organisation" || icon["Provider"] != "google" {
		t.Errorf("icon %v, want same-organisation of google", icon)
	}
	if brands, _ := metadata["ImpersonatedBrands"].([]any); len(brands) != 0 {
		t.Errorf("a brand's own page impersonates %v", brands)
	}
}

func TestFaviconUnresolvableMetadata(t *testing.T) {
	result := UnitTestKit.RunResponse(t, FaviconOriginTest.New(), "unresolvable_icon_href.http")
	if strings.Contains(result.Description, "own site") {
		t.Errorf("unresolvable icons described as the page's own: %s", result.Description)
	}
	icons, _ := UnitTestKit.Metadata(t, result)["Icons"].([]any)
	if len(icons) != 2 {
		t.Fatalf("icons %v, want two", icons)
	}
	for _, icon := range icons {
		if origin := icon.(map[string]any)["Origin"]; origin != "unresolvable" {
			t.Errorf("icon %v classified %v, want unresolvable", icon, origin)
		}
	}
}

func TestFaviconGitHubPagesSiblingMetadata(t *testing.T) {
	metadata := UnitTestKit.Metadata(t, UnitTestKit.RunResponse(t, FaviconOriginTest.New(), "github_pages_sibling_icon.http"))
	if metadata["PageDomain"] != "account-verify.github.io" {
		t.Errorf("PageDomain %v, want the GitHub Pages site itself", metadata["PageDomain"])
	}
	icons, _ := metadata["Icons"].([]any)
	if len(icons) != 1 || icons[0].(map[string]any)["Origin"] == "same-site" {
		t.Errorf("icons %v, the sibling site must not count as same-site", icons)
	}
}
