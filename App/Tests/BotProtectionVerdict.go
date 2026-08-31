// Package Tests provides security testing functionality for Engine-AntiGinx.
//
// # BotProtectionVerdict Module
//
// This module turns a scan that was stopped by a bot protection layer into a proper
// security verdict instead of a bare execution error.
//
// Rationale:
//
// Commercial protection products (Cloudflare, Akamai, DataDome, Incapsula and friends)
// have to be bought, configured and pointed at a domain by whoever controls its DNS.
// Phishing infrastructure is built to be cheap and short lived, so it very rarely sits
// behind a configured enterprise WAF. A target that answers with a genuine vendor
// challenge is therefore more likely to be an established, legitimate site than a
// throwaway credential harvester.
//
// "More likely" is not "certain". The signal is deliberately reported as a Low threat
// with a reduced certainty, because:
//   - Cloudflare's free tier is available to anyone, attackers included
//   - a protection layer hides the origin, so nothing behind it was actually tested
//   - a compromised legitimate site keeps its protection while serving phishing content
//
// The verdict exists to stop a blocked scan from reading as a security finding, while
// keeping it visible that no test actually ran against the origin.
package Tests

import (
	"fmt"
	"strings"
)

// BotProtectionTestName is the display name used for the verdict produced when a scan
// is stopped by a bot protection layer.
const BotProtectionTestName = "Bot Protection Block Assessment"

// HttpClient Error Codes that reach this module, named so the two ways a protection layer
// stops a scan can be told apart when the verdict is worded.
const (
	httpBlockedCode            = 102 // Target answered with a challenge instead of its content
	httpProtectionDetectedCode = 300 // Target answered normally, protection detected in front of it
)

// botProtectionCertainty is the confidence assigned to the "probably legitimate"
// reading of a bot protection block.
//
// It sits below the halfway mark on purpose: the inference is directional evidence,
// not a verified result, and no test was able to inspect the origin.
const botProtectionCertainty = 45

// BotProtectionMetadata carries the details of a blocked scan into the report.
//
// Fields:
//   - Protections: Vendor identified protection products that were detected
//   - BlockMessage: The raw HttpClient message describing why the scan stopped
//   - HttpErrorCode: The HttpClient Error Code that stopped the scan (httpBlockedCode or
//     httpProtectionDetectedCode)
//   - OriginTested: Always false, recorded explicitly so a consumer cannot mistake
//     this verdict for a completed assessment of the target
type BotProtectionMetadata struct {
	Protections   []string `json:"Protections"`
	BlockMessage  string   `json:"BlockMessage"`
	HttpErrorCode int      `json:"HttpErrorCode"`
	OriginTested  bool     `json:"OriginTested"`
}

// NewBotProtectionVerdict builds the TestResult reported when a scan could not reach the
// target because a bot protection layer answered instead.
//
// The result is classified as Low rather than as a failure: the presence of a configured
// protection product is weak positive evidence for the target's legitimacy. The certainty
// is held down and the description states the caveats explicitly, so the reading is never
// mistaken for a clean bill of health.
//
// Parameters:
//   - protections: Vendor identified protections (must be non-empty for the verdict to
//     be meaningful; callers check this before building a verdict)
//   - blockMessage: The HttpClient message explaining why the request failed
//   - httpErrorCode: The HttpClient Error Code that stopped the scan
//
// Returns:
//   - TestResult: Low threat verdict with reduced certainty and the full caveats
//
// Example:
//
//	result := NewBotProtectionVerdict(
//	    []string{"Cloudflare Server", "Cloudflare Ray ID: 8a1b2c3d"},
//	    "HTTP Status Code not 200 (OK): 403",
//	    102,
//	)
//	// result.ThreatLevel == Low, result.Certainty == 45
func NewBotProtectionVerdict(protections []string, blockMessage string, httpErrorCode int) TestResult {
	return TestResult{
		Name:        BotProtectionTestName,
		Certainty:   botProtectionCertainty,
		ThreatLevel: Low,
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
//
// The opening sentence distinguishes the two ways a protection layer stops a scan, because
// claiming the target refused the request when it in fact answered normally would misreport
// what happened:
//   - httpBlockedCode: the target answered with a challenge instead of its content
//   - httpProtectionDetectedCode: the target answered normally, and the engine declined to
//     test it because a protection layer was detected in front of it
//
// Parameters:
//   - protections: Vendor identified protections
//   - httpErrorCode: The HttpClient Error Code that stopped the scan
//
// Returns:
//   - string: Multi-sentence description for the report
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

	return opening + " " +
		"A configured commercial protection layer has to be set up by whoever controls the domain, " +
		"which phishing infrastructure rarely bothers with, so the target is more likely legitimate than not. " +
		"Treat this as weak evidence only: free protection tiers are available to attackers too, " +
		"a legitimate site can be compromised while keeping its protection in place, " +
		"and nothing behind the protection layer was actually verified. " +
		"Re-run with the anti-bot detection flag to attempt a real assessment."
}

// summarizeProtectionVendors reduces the raw detection strings to a readable list of
// distinct vendor names, so a report does not repeat "Cloudflare" once per matched header.
//
// Detection strings carry per-request detail (a Ray ID, a cache status). Only the leading
// vendor word is kept, and duplicates are dropped while preserving detection order.
//
// Parameters:
//   - protections: Raw detection strings from the HTTP client
//
// Returns:
//   - string: Comma-separated vendor names, or "unidentified vendor" when nothing usable
//     could be extracted
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

// extractVendorName pulls the vendor name out of a single detection string by keeping
// the leading word, which is where every detection in the HTTP client places it
// ("Cloudflare Ray ID: ...", "DataDome", "Incapsula Protection detected").
//
// Parameters:
//   - protection: A single detection string
//
// Returns:
//   - string: The vendor name, or an empty string when the input carries none
func extractVendorName(protection string) string {
	trimmed := strings.TrimSpace(protection)
	if trimmed == "" {
		return ""
	}

	fields := strings.Fields(trimmed)
	return strings.TrimSuffix(fields[0], ":")
}
