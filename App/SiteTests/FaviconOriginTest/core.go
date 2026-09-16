// Package FaviconOriginTest implements the Favicon Origin Analysis security test.
// See README.md for what it checks, how it grades and what it reports.
package FaviconOriginTest

import (
	"Engine-AntiGinx/App/SiteTests"
	"Engine-AntiGinx/App/SiteTests/FaviconOriginTest/modules"
	"fmt"
	"io"
	"strings"
)

// IconReference is one declared icon and where it is loaded from.
type IconReference = modules.IconReference

// FaviconOriginAnalysis is the evidence behind the favicon origin verdict.
type FaviconOriginAnalysis struct {
	PageURL            string          `json:"PageURL"`
	PageDomain         string          `json:"PageDomain"`
	Icons              []IconReference `json:"Icons"`
	ImpersonatedBrands []string        `json:"ImpersonatedBrands"`
}

// The stages own no data: the patterns and datasets in data.go are wired into them here.
var (
	extractor = modules.Extractor{
		Patterns:      markupPatterns,
		IconRelations: iconRelations,
	}

	classifier = modules.Classifier{
		BrandDomains: brandDomains,
		AssetHosts:   assetHostSuffixes,
	}
)

// originSeverity is how much each icon origin says about the page. Loading an icon from
// elsewhere has legitimate reasons, so on its own it never rises above Low: it is a signal to
// weigh next to the other phishing tests, not a verdict.
var originSeverity = map[string]SiteTests.ThreatLevel{
	modules.OriginSameHost:         SiteTests.None,
	modules.OriginSameSite:         SiteTests.None,
	modules.OriginInline:           SiteTests.None,
	modules.OriginSameOrganisation: SiteTests.None,
	modules.OriginUnresolvable:     SiteTests.None,
	modules.OriginAssetHost:        SiteTests.Info,
	modules.OriginForeign:          SiteTests.Info,
	modules.OriginIPAddress:        SiteTests.Low,
	modules.OriginBrand:            SiteTests.Low,
}

// New creates a new ResponseTest that checks which domains a page loads its favicon from.
func New() *SiteTests.ResponseTest {
	return &SiteTests.ResponseTest{
		Id:          TestId,
		Name:        TestName,
		Description: TestDescription,
		Category:    TestCategory,
		RunTest: func(params SiteTests.ResponseTestParams) SiteTests.TestResult {
			response := params.Response
			if response == nil || response.Request == nil || response.Request.URL == nil || response.Body == nil {
				return unreadableResult("The page address or content is unavailable, so its icon declarations could not be inspected.")
			}

			body, err := io.ReadAll(io.LimitReader(response.Body, maxScannedBody))
			if err != nil {
				return unreadableResult("The page content could not be read, so its icon declarations could not be inspected.")
			}

			page := response.Request.URL
			analysis := FaviconOriginAnalysis{
				PageURL:            page.String(),
				PageDomain:         SiteTests.RegistrableDomain(page.Hostname()),
				Icons:              []IconReference{},
				ImpersonatedBrands: []string{},
			}

			base := extractor.BaseURL(string(body), page)
			for _, declaration := range extractor.Declarations(string(body)) {
				icon := classifier.Classify(page, base, declaration)
				analysis.Icons = append(analysis.Icons, icon)
				if icon.Origin == modules.OriginBrand {
					analysis.ImpersonatedBrands = append(analysis.ImpersonatedBrands, icon.Provider)
				}
			}
			analysis.ImpersonatedBrands = SiteTests.UniqueStrings(analysis.ImpersonatedBrands)

			certainty := faviconFactCertainty
			if len(analysis.ImpersonatedBrands) > 0 {
				certainty = faviconBrandCertainty
			}

			return SiteTests.TestResult{
				Name:        TestName,
				Certainty:   certainty,
				ThreatLevel: evaluateFaviconThreatLevel(analysis),
				Metadata:    analysis,
				Description: buildFaviconDescription(analysis),
			}
		},
	}
}

// unreadableResult reports a page whose icon declarations could not be inspected.
func unreadableResult(description string) SiteTests.TestResult {
	return SiteTests.TestResult{
		Name:        TestName,
		Certainty:   faviconUnreadable,
		ThreatLevel: SiteTests.Info,
		Metadata:    nil,
		Description: description,
	}
}

// evaluateFaviconThreatLevel is the most severe origin any declared icon is loaded from.
func evaluateFaviconThreatLevel(analysis FaviconOriginAnalysis) SiteTests.ThreatLevel {
	levels := make([]SiteTests.ThreatLevel, 0, len(analysis.Icons))
	for _, icon := range analysis.Icons {
		levels = append(levels, originSeverity[icon.Origin])
	}
	return SiteTests.HighestThreatLevel(levels...)
}

// buildFaviconDescription renders the finding in the operator's terms, most severe first.
func buildFaviconDescription(analysis FaviconOriginAnalysis) string {
	if len(analysis.Icons) == 0 {
		return "The page declares no icon, so browsers request /favicon.ico from the page's own origin."
	}

	hostsByOrigin := map[string][]string{}
	for _, icon := range analysis.Icons {
		label := icon.Host
		if icon.Provider != "" && icon.Origin != modules.OriginBrand {
			label += " (" + icon.Provider + ")"
		}
		hostsByOrigin[icon.Origin] = SiteTests.UniqueStrings(append(hostsByOrigin[icon.Origin], label))
	}

	sentences := []string{}
	if hosts := hostsByOrigin[modules.OriginBrand]; len(hosts) > 0 {
		sentences = append(sentences, fmt.Sprintf(
			"The page loads its icon from %s, a domain of %s, while being served from %s. Phishing kits borrow a brand's icon this way to look authentic, but partners, resellers and integrations of the brand do it too, so this is worth weighing next to the other findings rather than conclusive on its own.",
			strings.Join(hosts, ", "), strings.Join(analysis.ImpersonatedBrands, ", "), analysis.PageDomain))
	}
	if hosts := hostsByOrigin[modules.OriginIPAddress]; len(hosts) > 0 {
		sentences = append(sentences, fmt.Sprintf(
			"The page loads its icon from the bare address %s, infrastructure without a name that a site is rarely built on, though a misconfigured or internal deployment can reference one.",
			strings.Join(hosts, ", ")))
	}
	if hosts := hostsByOrigin[modules.OriginForeign]; len(hosts) > 0 {
		sentences = append(sentences, fmt.Sprintf(
			"The page loads its icon from %s, a domain unrelated to %s. Legitimate sites do this when they share assets across the domains of one organisation, but it is also how a copied page keeps pointing at the site it was copied from.",
			strings.Join(hosts, ", "), analysis.PageDomain))
	}
	if hosts := hostsByOrigin[modules.OriginAssetHost]; len(hosts) > 0 {
		sentences = append(sentences, fmt.Sprintf(
			"The page loads its icon from %s, a content delivery network or site platform serving assets for its customers.",
			strings.Join(hosts, ", ")))
	}

	if len(sentences) == 0 {
		return fmt.Sprintf("All %d declared icon(s) are loaded from the page's own site or embedded in the page.", len(analysis.Icons))
	}
	return strings.Join(sentences, " ")
}
