package BotProtectionTest

import (
	"Engine-AntiGinx/App/Detection"
	"Engine-AntiGinx/App/SiteTests"
	"fmt"
	"strings"
)

// The package has two entry points, and they answer the same question from opposite
// situations. New() is the test proper: it probes the target itself and reports what sits
// in front of it. NewVerdict() is called by the scheduler when the main request was
// stopped by a protection layer and there is no response for any Response test to read —
// the block itself is then the only evidence available, and it is worth reporting rather
// than discarding.

// BotProtectionScanMetadata is the detailed outcome of the bot protection probe.
type BotProtectionScanMetadata struct {
	Presence   []string `json:"Presence"`
	Challenge  []string `json:"Challenge"`
	StatusCode int      `json:"StatusCode"`
	Blocked    bool     `json:"Blocked"`
	Reachable  bool     `json:"Reachable"`
}

// New creates a new PreResponseTest that identifies the bot protection or CDN/WAF layer
// sitting in front of the target.
func New() *SiteTests.PreResponseTest {
	return &SiteTests.PreResponseTest{
		Id:          "bot-protection",
		Name:        TestName,
		Description: "Identifies the bot protection, CDN or WAF layer in front of the target and whether it withholds content behind a challenge",
		Category:    Category,
		RunTest: func(params SiteTests.PreResponseTestParams) SiteTests.TestResult {
			report, err := Detection.Probe(params.Target)
			if err != nil {
				return SiteTests.TestResult{
					Name:        TestName,
					Certainty:   botProtectionFactCertainty,
					ThreatLevel: SiteTests.Info,
					Metadata: BotProtectionScanMetadata{
						Presence:  []string{},
						Challenge: []string{},
						Reachable: false,
					},
					Description: "The target could not be reached, so no conclusion about a bot " +
						"protection layer can be drawn: " + err.Error(),
				}
			}

			metadata := BotProtectionScanMetadata{
				Presence:   report.Presence,
				Challenge:  report.Challenge,
				StatusCode: report.StatusCode,
				Blocked:    report.IsBlocked(),
				Reachable:  true,
			}
			if metadata.Presence == nil {
				metadata.Presence = []string{}
			}
			if metadata.Challenge == nil {
				metadata.Challenge = []string{}
			}

			if !report.HasProtection() {
				return SiteTests.TestResult{
					Name:        TestName,
					Certainty:   botProtectionFactCertainty,
					ThreatLevel: SiteTests.Info,
					Metadata:    metadata,
					Description: fmt.Sprintf(
						"The target answered with status %d and no bot protection, CDN or WAF layer "+
							"was identified in front of it. The remaining tests therefore observe the "+
							"origin directly.",
						report.StatusCode,
					),
				}
			}

			return SiteTests.TestResult{
				Name:        TestName,
				Certainty:   botProtectionCertainty,
				ThreatLevel: SiteTests.Low,
				Metadata:    metadata,
				Description: buildBotProtectionScanDescription(report),
			}
		},
	}
}

// buildBotProtectionScanDescription renders the operator-facing explanation of a probe that
// did find a protection layer, stating what was found and how much it is worth.
func buildBotProtectionScanDescription(report Detection.Report) string {
	vendors := summarizeProtectionVendors(report.All())

	opening := fmt.Sprintf(
		"The target is served through a bot protection, CDN or WAF layer (%s), and answered "+
			"the probe with status %d. Content was returned normally, so the remaining tests "+
			"observe the site itself rather than a challenge page.",
		vendors, report.StatusCode,
	)
	if report.IsBlocked() {
		opening = fmt.Sprintf(
			"The target answered the probe with status %d and served a challenge from its bot "+
				"protection layer (%s) instead of its content:\n%s"+
				"Tests that need the page body cannot reach the origin in this state.",
			report.StatusCode, vendors, Detection.FormatList(report.Challenge),
		)
	}

	return opening + " " + botProtectionLegitimacyCaveat
}

// BotProtectionMetadata carries the details of a blocked scan into the report.
type BotProtectionMetadata struct {
	Protections   []string `json:"Protections"`
	BlockMessage  string   `json:"BlockMessage"`
	HttpErrorCode int      `json:"HttpErrorCode"`
	OriginTested  bool     `json:"OriginTested"`
}

// NewVerdict builds the TestResult reported when a scan could not reach the target because a
// bot protection layer answered instead.
func NewVerdict(protections []string, blockMessage string, httpErrorCode int) SiteTests.TestResult {
	return SiteTests.TestResult{
		Name:        TestName,
		Certainty:   botProtectionCertainty,
		ThreatLevel: SiteTests.Low,
		Metadata: BotProtectionMetadata{
			Protections:   protections,
			BlockMessage:  blockMessage,
			HttpErrorCode: httpErrorCode,
			OriginTested:  false,
		},
		Description: buildBotProtectionDescription(protections, httpErrorCode),
	}
}

// buildBotProtectionDescription renders the human-readable explanation of a stopped scan,
// including the reasoning and the reasons that reasoning can be wrong.
func buildBotProtectionDescription(protections []string, httpErrorCode int) string {
	vendors := summarizeProtectionVendors(protections)

	opening := fmt.Sprintf(
		"The target responded normally, but the scan was stopped because a bot protection layer (%s) "+
			"was detected in front of it, so no test was executed.",
		vendors,
	)
	if httpErrorCode == httpBlockedCode {
		opening = fmt.Sprintf(
			"The scan was blocked by bot protection (%s), so no test could reach the origin.",
			vendors,
		)
	}

	return opening + " " + botProtectionLegitimacyCaveat
}

// summarizeProtectionVendors reduces the raw detection strings to a readable list of distinct
// vendor names, so a report does not repeat "Cloudflare" once per matched header.
func summarizeProtectionVendors(protections []string) string {
	seen := make(map[string]bool)
	var vendors []string

	for _, protection := range protections {
		vendor := extractVendorName(protection)
		if vendor == "" || seen[vendor] {
			continue
		}
		seen[vendor] = true
		vendors = append(vendors, vendor)
	}

	if len(vendors) == 0 {
		return "unidentified vendor"
	}
	return strings.Join(vendors, ", ")
}

// extractVendorName pulls the vendor name out of a single detection string by keeping the
// leading word, which is where every vendor detection places it ("Cloudflare Ray ID: ...",
// "DataDome", "Incapsula Protection detected").
func extractVendorName(protection string) string {
	trimmed := strings.TrimSpace(protection)
	if trimmed == "" || strings.HasPrefix(trimmed, keywordIndicatorPrefix) {
		return ""
	}

	fields := strings.Fields(trimmed)
	return strings.TrimSuffix(fields[0], ":")
}
