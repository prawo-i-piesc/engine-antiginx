package Tests

import (
	"Engine-AntiGinx/App/Detection"
	"fmt"
)

// BotProtectionCategory is the category worn by every test that reports on a bot
// protection layer. The scheduler matches on it to tell whether such a test is already
// part of a scan, so it can leave the verdict to the test instead of synthesizing a
// competing one from a failed request.
const BotProtectionCategory = "Bot-Protection"

// botProtectionFactCertainty is used for statements the probe establishes directly:
// the target was unreachable, or no protection layer was identified at all.
const botProtectionFactCertainty = 100

// BotProtectionScanMetadata is the detailed outcome of the bot protection probe.
//
// Presence and Challenge are kept apart because they support very different conclusions:
// a CDN fingerprint says the target is proxied, while a challenge says content was
// actually withheld. Collapsing the two is what previously made every Cloudflare-fronted
// site look blocked.
//
// Fields:
//   - Presence: CDN/WAF vendors identified in front of the target
//   - Challenge: Evidence that an interstitial was served instead of content
//   - StatusCode: Status returned to the probe, 0 when the target was unreachable
//   - Blocked: Whether the probe was served a challenge rather than content
//   - Reachable: Whether the probe got any response at all
type BotProtectionScanMetadata struct {
	Presence   []string `json:"Presence"`
	Challenge  []string `json:"Challenge"`
	StatusCode int      `json:"StatusCode"`
	Blocked    bool     `json:"Blocked"`
	Reachable  bool     `json:"Reachable"`
}

// NewBotProtectionTest creates a new PreResponseTest that identifies the bot protection
// or CDN/WAF layer sitting in front of the target.
//
// The test issues its own probe rather than reading the main scan response, for two
// reasons. It has to reach a verdict precisely in the case where the main request was
// blocked and there is no response to inspect; and keeping the detection out of the
// transport layer stops a CDN fingerprint from deciding the fate of the whole scan.
//
// Threat level assessment:
//   - Info (1): Target unreachable, or no protection layer identified
//   - Low (2): A protection layer was identified, whether or not it challenged the probe
//
// A protection layer is reported as Low rather than as a vulnerability because it is weak
// evidence about legitimacy, not a misconfiguration: a commercial protection product has
// to be set up by whoever controls the domain, which throwaway phishing infrastructure
// rarely bothers with.
//
// Returns:
//   - *PreResponseTest: Configured bot protection test ready for execution
//
// Example:
//
//	test := NewBotProtectionTest()
//	result := test.Run(ScanContext{Target: target})
func NewBotProtectionTest() *PreResponseTest {
	return &PreResponseTest{
		Id:          "bot-protection",
		Name:        BotProtectionTestName,
		Description: "Identifies the bot protection, CDN or WAF layer in front of the target and whether it withholds content behind a challenge",
		Category:    BotProtectionCategory,
		RunTest: func(params PreResponseTestParams) TestResult {
			report, err := Detection.Probe(params.Target)
			if err != nil {
				return TestResult{
					Name:        BotProtectionTestName,
					Certainty:   botProtectionFactCertainty,
					ThreatLevel: Info,
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
				return TestResult{
					Name:        BotProtectionTestName,
					Certainty:   botProtectionFactCertainty,
					ThreatLevel: Info,
					Metadata:    metadata,
					Description: fmt.Sprintf(
						"The target answered with status %d and no bot protection, CDN or WAF layer "+
							"was identified in front of it. The remaining tests therefore observe the "+
							"origin directly.",
						report.StatusCode,
					),
				}
			}

			return TestResult{
				Name:        BotProtectionTestName,
				Certainty:   botProtectionCertainty,
				ThreatLevel: Low,
				Metadata:    metadata,
				Description: buildBotProtectionScanDescription(report),
			}
		},
	}
}

// buildBotProtectionScanDescription renders the operator-facing explanation of a probe
// that did find a protection layer, stating what was found and how much it is worth.
//
// Parameters:
//   - report: The probe outcome, known to contain at least one indicator
//
// Returns:
//   - string: Human-readable description of the finding
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
