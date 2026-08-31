// Package Tests provides security testing functionality for Engine-AntiGinx.
//
// # PhishingURLTest Module
//
// This module analyzes the target URL for phishing indicators along two
// complementary dimensions: who the hostname pretends to be, and what the rest
// of the URL carries. Both are required, because a phishing link can use a
// perfect lookalike domain with harmless parameters, or a throwaway domain with
// a fully assembled credential harvesting query string.
//
// Hostname Impersonation:
//   - Single-character typos (e.g., "gogle.com" instead of "google.com")
//   - Adjacent-character transpositions (e.g., "goolge.com")
//   - Popular letter replacements (e.g., "m" replaced with "rn")
//   - Homograph attacks using confusable Unicode characters (Cyrillic, Greek, etc.)
//
// URL Parameter Abuse:
//   - Credentials embedded in the URL (https://user:pass@host/ or ?password=...)
//   - Session, authentication and payment data in the query string
//   - Victim identity parameters used to pre-fill a phishing landing page
//   - Brand keywords placed in the path or query while the host is unrelated
//   - Open-redirect parameters pointing to an external host
//   - Base64 encoded URLs or e-mail addresses hidden inside parameter values
//   - Dangerous schemes in parameter values (javascript:, data:, vbscript:, file:)
//   - Structural anomalies (IP literal host, oversized query, phishing path keywords)
//
// Threat Level:
//
// Each dimension is evaluated independently and the higher classification wins.
// When both dimensions report at least Medium, the result is escalated by one
// level, since a lookalike hostname that also harvests data describes a complete
// phishing page rather than an isolated anomaly.
//
// Privacy note: parameter values are never copied into the result metadata.
// Only parameter names and a redacted form of the URL are reported, so a scan
// report can never leak the very credentials this test warns about.
package Tests

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"unicode/utf8"
)

var popularDomainDatabase = map[string][]string{
	"google": {
		"google.com", "gmail.com", "googlemail.com", "google.co.uk", "google.de", "google.fr", "google.pl", "google.it", "google.es", "google.ca", "google.com.br", "google.com.au",
	},
	"microsoft": {
		"microsoft.com", "live.com", "outlook.com", "office.com", "office365.com", "microsoftonline.com", "skype.com", "xbox.com", "bing.com", "linkedin.com",
	},
	"apple": {
		"apple.com", "icloud.com", "me.com", "mac.com", "itunes.com",
	},
	"amazon": {
		"amazon.com", "amazon.co.uk", "amazon.de", "amazon.fr", "amazon.pl", "amazon.it", "amazon.es", "amazon.ca", "amazon.in", "amazon.com.au", "amazonaws.com",
	},
	"meta": {
		"facebook.com", "fb.com", "messenger.com", "instagram.com", "threads.net", "whatsapp.com",
	},
	"x": {
		"x.com", "twitter.com", "t.co",
	},
	"youtube": {
		"youtube.com", "youtu.be",
	},
	"tiktok": {
		"tiktok.com",
	},
	"snapchat": {
		"snapchat.com",
	},
	"paypal": {
		"paypal.com", "paypalobjects.com", "venmo.com", "braintreepayments.com",
	},
	"stripe": {
		"stripe.com",
	},
	"wise": {
		"wise.com",
	},
	"revolut": {
		"revolut.com",
	},
	"payoneer": {
		"payoneer.com",
	},
	"cashapp": {
		"cash.app",
	},
	"chase": {
		"chase.com", "jpmorganchase.com",
	},
	"bankofamerica": {
		"bankofamerica.com",
	},
	"wellsfargo": {
		"wellsfargo.com",
	},
	"citi": {
		"citi.com", "citibank.com",
	},
	"capitalone": {
		"capitalone.com",
	},
	"hsbc": {
		"hsbc.com",
	},
	"santander": {
		"santander.com",
	},
	"americanexpress": {
		"americanexpress.com", "amex.com",
	},
	"visa": {
		"visa.com",
	},
	"mastercard": {
		"mastercard.com",
	},
	"github": {
		"github.com", "github.io",
	},
	"gitlab": {
		"gitlab.com",
	},
	"bitbucket": {
		"bitbucket.org",
	},
	"atlassian": {
		"atlassian.com", "jira.com", "trello.com",
	},
	"docker": {
		"docker.com", "docker.io",
	},
	"cloudflare": {
		"cloudflare.com",
	},
	"aws": {
		"aws.amazon.com", "amazonaws.com",
	},
	"azure": {
		"azure.com", "windowsazure.com",
	},
	"gcp": {
		"cloud.google.com", "withgoogle.com",
	},
	"dropbox": {
		"dropbox.com",
	},
	"slack": {
		"slack.com",
	},
	"zoom": {
		"zoom.us",
	},
	"discord": {
		"discord.com", "discord.gg",
	},
	"telegram": {
		"telegram.org", "t.me",
	},
	"netflix": {
		"netflix.com",
	},
	"spotify": {
		"spotify.com",
	},
	"disney": {
		"disneyplus.com", "disney.com",
	},
	"steam": {
		"steampowered.com", "steamcommunity.com",
	},
	"epicgames": {
		"epicgames.com", "unrealengine.com",
	},
	"ea": {
		"ea.com", "origin.com",
	},
	"nintendo": {
		"nintendo.com",
	},
	"sony": {
		"sony.com", "playstation.com",
	},
	"booking": {
		"booking.com",
	},
	"airbnb": {
		"airbnb.com",
	},
	"uber": {
		"uber.com", "ubereats.com",
	},
	"lyft": {
		"lyft.com",
	},
	"ebay": {
		"ebay.com", "ebay.co.uk", "ebay.de", "ebay.fr",
	},
	"aliexpress": {
		"aliexpress.com",
	},
	"etsy": {
		"etsy.com",
	},
	"wikipedia": {
		"wikipedia.org", "wikimedia.org",
	},
	"adobe": {
		"adobe.com", "behance.net",
	},
	"canva": {
		"canva.com",
	},
	"salesforce": {
		"salesforce.com",
	},
	"shopify": {
		"shopify.com", "myshopify.com",
	},
	"coinbase": {
		"coinbase.com",
	},
	"binance": {
		"binance.com",
	},
	"kraken": {
		"kraken.com",
	},
	"metamask": {
		"metamask.io",
	},
	"openai": {
		"openai.com", "chatgpt.com",
	},
	"notion": {
		"notion.so",
	},
	"figma": {
		"figma.com",
	},
	"reddit": {
		"reddit.com",
	},
	"quora": {
		"quora.com",
	},
	"yahoo": {
		"yahoo.com",
	},
}

var popularLetterReplacementDatabase = map[string][]string{
	"m": {"rn", "nn"},
	"w": {"vv"},
	"d": {"cl"},
	"n": {"ri"},
	"u": {"v"},
	"v": {"u"},
	"k": {"lc"},
	"h": {"lh", "ii"},
	"b": {"6", "8"},
	"g": {"9", "q"},
	"q": {"g"},
	"l": {"1", "i"},
	"i": {"1", "l"},
	"o": {"0"},
	"e": {"3"},
	"a": {"4"},
	"s": {"5"},
	"t": {"7"},
	"z": {"2"},
	"x": {"kz"},
}

var confusableRuneDatabase = map[rune]rune{
	'а': 'a', // Cyrillic a
	'е': 'e', // Cyrillic e
	'о': 'o', // Cyrillic o
	'р': 'p', // Cyrillic er
	'с': 'c', // Cyrillic es
	'у': 'y', // Cyrillic u
	'х': 'x', // Cyrillic ha
	'к': 'k', // Cyrillic ka
	'м': 'm', // Cyrillic em
	'т': 't', // Cyrillic te
	'в': 'b', // Cyrillic ve
	'н': 'h', // Cyrillic en
	'і': 'i', // Cyrillic i
	'ј': 'j', // Cyrillic je
	'ԁ': 'd', // Cyrillic-like d
	'գ': 'g', // Armenian g
	'ο': 'o', // Greek omicron
	'ρ': 'p', // Greek rho
	'ν': 'v', // Greek nu
	'τ': 't', // Greek tau
	'ι': 'i', // Greek iota
	'κ': 'k', // Greek kappa
	'χ': 'x', // Greek chi
	'ʟ': 'l', // Latin small capital L
}

// NewPhishingURLTest creates and returns a new ResponseTest instance for phishing detection.
// The test combines two independent analyses of the request URL:
//
//   - Hostname analysis: detects domain impersonation through typo-squatting
//     (deliberate misspellings, transpositions, letter replacements) and homograph
//     attacks using confusable Unicode characters
//   - Parameter analysis: detects credentials embedded in the URL, sensitive data
//     carried in the query string, victim targeting, open redirects, encoded
//     payloads and structural anomalies
//
// Test Workflow:
//
//  1. Extract URL: Take the final request URL from the HTTP response
//  2. Hostname Analysis: Compare the host against the popular domain dataset
//  3. Parameter Analysis: Classify every parameter name and inspect its value
//  4. Threat Evaluation: Take the higher classification of both dimensions and
//     escalate when both of them report a finding
//  5. Generate Report: Produce a combined, value-free description
//
// Certainty:
//
// The test reports 100% certainty when the URL is clean, 95% for deterministic
// findings (a lookalike hostname or credentials present in the URL) and 85% when
// the verdict rests on parameter heuristics alone, where legitimate applications
// may occasionally match (for example an OAuth "code" parameter on a genuine
// authorization callback).
//
// Returns a configured ResponseTest ready for execution against HTTP responses.
//
// Example:
//
//	phishingTest := NewPhishingURLTest()
//	result := phishingTest.Run(ResponseTestParams{Response: httpResponse})
//	if result.ThreatLevel != None {
//	    fmt.Printf("Phishing risk detected: %s\n", result.Description)
//	}
//
//	// https://example.com/products?id=42                   → None
//	// https://gooele.com/                                  → Medium
//	// https://example.com/login?user=bob&password=hunter2  → Critical
//	// https://gooele.com/signin?email=bob@corp.tld         → High
//
// Related Tests:
//   - CookieSecurityTest: Analyzes session material carried in cookies
//   - SSLCertificateSecurityTest: Analyzes the certificate presented by the host
func NewPhishingURLTest() *ResponseTest {
	return &ResponseTest{
		Id:          "phishing-url",
		Name:        "Phishing URL Analysis",
		Description: "Analyzes the hostname for typo-squatting and homograph patterns and the URL parameters for embedded credentials, sensitive data and redirection abuse",
		Category:    "Phishing",
		RunTest: func(params ResponseTestParams) TestResult {
			target := extractRequestURL(params)
			if target == nil {
				return TestResult{
					Name:        "Phishing URL Analysis",
					Certainty:   100,
					ThreatLevel: Info,
					Metadata: map[string]any{
						"url":  "",
						"host": "",
					},
					Description: "Request URL is unavailable, phishing analysis could not be performed",
				}
			}

			host := strings.ToLower(strings.TrimSuffix(target.Hostname(), "."))
			domainAnalysis := analyzePhishingDomain(host)
			parameterAnalysis := analyzeURLParameters(target)

			domainThreat := evaluatePhishingThreatLevel(domainAnalysis)
			parameterThreat := evaluateURLParameterThreatLevel(parameterAnalysis)

			return TestResult{
				Name:        "Phishing URL Analysis",
				Certainty:   evaluatePhishingCertainty(domainAnalysis, parameterAnalysis),
				ThreatLevel: combinePhishingThreatLevels(domainThreat, parameterThreat),
				Metadata:    combinePhishingAnalyses(host, domainAnalysis, parameterAnalysis),
				Description: generateCombinedPhishingDescription(domainAnalysis, parameterAnalysis),
			}
		},
	}
}

// combinePhishingThreatLevels merges the classifications of both analysis dimensions
// into the threat level reported by the test.
//
// Combination logic:
//   - The higher of the two classifications is taken as the baseline, so a finding
//     in either dimension is never diluted by a clean result in the other one
//   - When both dimensions report at least Medium, the result is escalated by one
//     level (capped at Critical), because an impersonating hostname that also
//     harvests or targets data is a complete phishing page rather than an isolated
//     anomaly of a legitimate site
//
// Parameters:
//   - domainThreat: Classification produced by evaluatePhishingThreatLevel
//   - parameterThreat: Classification produced by evaluateURLParameterThreatLevel
//
// Returns the combined ThreatLevel.
func combinePhishingThreatLevels(domainThreat ThreatLevel, parameterThreat ThreatLevel) ThreatLevel {
	combined := domainThreat
	if parameterThreat > combined {
		combined = parameterThreat
	}

	if domainThreat >= Medium && parameterThreat >= Medium && combined < Critical {
		combined++
	}

	return combined
}

// evaluatePhishingCertainty determines the confidence reported for the combined result.
//
// Confidence levels:
//   - 100%: No indicator was found in either dimension
//   - 95%: The verdict rests on deterministic evidence - a hostname matched against
//     the popular domain dataset, or credentials actually present in the URL
//   - 85%: The verdict rests on parameter heuristics alone, which legitimate
//     applications may occasionally trigger
//
// Parameters:
//   - domainAnalysis: Metadata produced by analyzePhishingDomain
//   - parameterAnalysis: Metadata produced by analyzeURLParameters
//
// Returns the confidence percentage of the finding.
func evaluatePhishingCertainty(domainAnalysis map[string]any, parameterAnalysis map[string]any) int {
	domainSuspicious, _ := domainAnalysis["is_suspicious"].(bool)
	parameterSuspicious, _ := parameterAnalysis["is_suspicious"].(bool)

	if !domainSuspicious && !parameterSuspicious {
		return 100
	}

	if parameterSuspicious {
		embedded, _ := parameterAnalysis["embedded_credentials"].(bool)
		credentials, _ := parameterAnalysis["credential_parameters"].([]string)
		if !embedded && len(credentials) == 0 {
			return 85
		}
	}

	return 95
}

// combinePhishingAnalyses merges the metadata of both analysis dimensions into the
// single map reported by the test. Each dimension keeps its own nested object, so
// no key of one analysis can shadow a key of the other, while the fields needed for
// a quick verdict are lifted to the top level.
//
// Parameters:
//   - host: The analyzed hostname
//   - domainAnalysis: Metadata produced by analyzePhishingDomain
//   - parameterAnalysis: Metadata produced by analyzeURLParameters
//
// Returns a map containing:
//   - url: The analyzed URL with every secret replaced by the redaction placeholder
//   - host: The analyzed hostname
//   - is_suspicious: Boolean indicating whether either dimension found an indicator
//   - detected_patterns: All indicators of both dimensions
//   - domain_analysis: Full hostname impersonation metadata
//   - parameter_analysis: Full URL parameter metadata
func combinePhishingAnalyses(host string, domainAnalysis map[string]any, parameterAnalysis map[string]any) map[string]any {
	domainSuspicious, _ := domainAnalysis["is_suspicious"].(bool)
	parameterSuspicious, _ := parameterAnalysis["is_suspicious"].(bool)
	domainPatterns, _ := domainAnalysis["detected_patterns"].([]string)
	parameterPatterns, _ := parameterAnalysis["detected_patterns"].([]string)

	patterns := make([]string, 0, len(domainPatterns)+len(parameterPatterns))
	patterns = append(patterns, domainPatterns...)
	patterns = append(patterns, parameterPatterns...)

	return map[string]any{
		"url":                parameterAnalysis["url"],
		"host":               host,
		"is_suspicious":      domainSuspicious || parameterSuspicious,
		"detected_patterns":  patterns,
		"domain_analysis":    domainAnalysis,
		"parameter_analysis": parameterAnalysis,
	}
}

// generateCombinedPhishingDescription joins the descriptions of both analysis
// dimensions into the single human-readable summary reported by the test, so a
// reader always learns what the hostname and the parameters each contributed.
//
// Parameters:
//   - domainAnalysis: Metadata produced by analyzePhishingDomain
//   - parameterAnalysis: Metadata produced by analyzeURLParameters
//
// Returns the combined description suitable for security reports.
func generateCombinedPhishingDescription(domainAnalysis map[string]any, parameterAnalysis map[string]any) string {
	return fmt.Sprintf(
		"Hostname: %s. URL parameters: %s",
		generatePhishingDescription(domainAnalysis),
		generateURLParameterDescription(parameterAnalysis),
	)
}

// analyzePhishingDomain performs comprehensive phishing analysis on a given hostname.
// It checks the hostname against a database of legitimate popular domains and applies
// multiple detection techniques to identify phishing attempts.
//
// Analysis steps:
//  1. First checks if the hostname is a known legitimate domain (early exit for safety)
//  2. Compares the hostname against database of legitimate domains using four detection vectors:
//     - Single edit distance (Levenshtein distance of 1)
//     - Adjacent character transpositions
//     - Popular character replacements (e.g., m→rn, x→х)
//     - Homograph attacks using confusable Unicode characters
//
// An empty hostname yields a clean, non-suspicious result.
//
// Parameters:
//   - host: The hostname to analyze (e.g., "example.com", "gooele.com")
//
// Returns a map containing analysis metadata:
//   - host: The analyzed hostname
//   - is_suspicious: Boolean indicating if phishing patterns were detected
//   - is_known_legitimate: Boolean indicating if the domain is in the legitimate database
//   - matched_brand: The brand/company name of the likely target (e.g., "google")
//   - matched_legitimate_domain: The legitimate domain being impersonated
//   - detected_patterns: List of phishing patterns detected
//   - lookalike_examples: Examples of the detected phishing attempt
//   - homograph_char_count: Number of confusable Unicode characters detected (for severity assessment)
func analyzePhishingDomain(host string) map[string]any {
	popularDomains := popularDomainDatabase
	legalDomains := make(map[string]string)

	for brand, domains := range popularDomains {
		for _, d := range domains {
			legalDomains[d] = brand
		}
	}

	replacements := popularLetterReplacementDatabase
	match := map[string]any{
		"host":                      host,
		"is_suspicious":             false,
		"matched_brand":             "",
		"matched_legitimate_domain": "",
		"detected_patterns":         []string{},
		"lookalike_examples":        []string{},
		"is_known_legitimate":       false,
		"homograph_char_count":      0,
	}

	// Without a hostname there is nothing to compare against, so the analysis
	// reports no findings instead of matching the empty string against the dataset.
	if host == "" {
		return match
	}

	if _, ok := legalDomains[host]; ok {
		match["is_known_legitimate"] = true
		match["matched_brand"] = legalDomains[host]
		match["matched_legitimate_domain"] = host
		return match
	}

	for brand, domains := range popularDomains {
		for _, legit := range domains {
			patterns := []string{}

			if hasSameSuffix(host, legit) && isSingleEditDistance(host, legit) {
				patterns = append(patterns, "single-character typo")
			}

			if hasSameSuffix(host, legit) && isTranspositionVariant(host, legit) {
				patterns = append(patterns, "adjacent-letter transposition")
			}

			if hasSameSuffix(host, legit) && matchesReplacementVariant(host, legit, replacements) {
				patterns = append(patterns, "popular letter replacement")
			}

			if looksLikeConfusableHomograph(host, legit) {
				count := countConfusableCharacters(host)
				if count > 0 {
					patterns = append(patterns, "homograph/confusable character")
					match["homograph_char_count"] = count
				}
			}

			if len(patterns) > 0 {
				match["is_suspicious"] = true
				match["matched_brand"] = brand
				match["matched_legitimate_domain"] = legit
				match["detected_patterns"] = uniqueStrings(patterns)
				match["lookalike_examples"] = []string{fmt.Sprintf("%s resembles %s", host, legit)}
				return match
			}
		}
	}

	return match
}

// evaluatePhishingThreatLevel determines the security threat classification based on
// the detected phishing patterns and analysis metadata.
//
// Threat level assignment logic:
//   - ThreatLevel.None: Not suspicious, or no suspicious patterns detected
//   - ThreatLevel.Medium: Single phishing pattern detected (typo, transposition, or replacement)
//   - ThreatLevel.High: Multiple phishing patterns detected, or homograph attack with isolated confusable characters
//   - ThreatLevel.Critical: Multiple phishing patterns combined with significant homograph usage
//     (highest severity due to sophisticated multi-vector evasion technique)
//
// Homograph character severity assessment:
//   - Isolated confusable character (1-2): Treated as Medium unless combined with other patterns
//   - Moderate confusable character usage (3+): Raises to High if combined with other patterns
//   - Multiple patterns + homograph: Escalates to Critical
//
// Parameters:
//   - metadata: Analysis metadata map from analyzePhishingDomain containing detected patterns
//
// Returns the assigned ThreatLevel based on the patterns and attack sophistication.
func evaluatePhishingThreatLevel(metadata map[string]any) ThreatLevel {
	isSuspicious, _ := metadata["is_suspicious"].(bool)
	if !isSuspicious {
		return None
	}

	patterns, _ := metadata["detected_patterns"].([]string)
	homographCount, _ := metadata["homograph_char_count"].(int)

	// Multiple patterns combined with homograph → Critical
	if len(patterns) >= 2 && homographCount > 0 {
		return Critical
	}

	// Multiple patterns without homograph → High
	if len(patterns) >= 2 {
		return High
	}

	// Single homograph pattern with significant character usage → High
	hasHomograph := false
	for _, p := range patterns {
		if p == "homograph/confusable character" {
			hasHomograph = true
			break
		}
	}

	if hasHomograph && homographCount >= 3 {
		return High
	}

	// Single pattern (including isolated homograph) → Medium
	return Medium
}

// generatePhishingDescription creates a human-readable description of the phishing analysis results.
// The description provides actionable information about what phishing indicators were detected
// and which legitimate domain is being impersonated.
//
// Description types:
//   - For legitimate domains: Confirms domain is recognized as legitimate
//   - For clean domains: Reports no phishing indicators detected
//   - For suspicious domains: Describes the target brand, impersonated domain, and attack patterns
//
// Parameters:
//   - metadata: Analysis results map from analyzePhishingDomain
//
// Returns a detailed, user-friendly description suitable for security reports.
func generatePhishingDescription(metadata map[string]any) string {
	isLegit, _ := metadata["is_known_legitimate"].(bool)
	if isLegit {
		return "Domain is recognized as a known legitimate domain from the local popularity dataset"
	}

	isSuspicious, _ := metadata["is_suspicious"].(bool)
	if !isSuspicious {
		return "No phishing-style typo-squatting or homograph indicators detected against the local popular-domain dataset"
	}

	host, _ := metadata["host"].(string)
	brand, _ := metadata["matched_brand"].(string)
	legit, _ := metadata["matched_legitimate_domain"].(string)
	patterns, _ := metadata["detected_patterns"].([]string)

	return fmt.Sprintf(
		"Potential phishing domain detected: %s appears to impersonate %s (%s). Detected patterns: %s",
		host,
		brand,
		legit,
		strings.Join(patterns, ", "),
	)
}

// looksLikeConfusableHomograph detects homograph attacks using visually similar Unicode characters.
// These attacks use confusable characters (especially Cyrillic, Greek, or other scripts) to create
// domains that look identical to legitimate domains when viewed in a browser but are technically different.
//
// Detection method:
//  1. Normalizes both hostnames using the confusable character map
//  2. Checks if normalized versions are identical
//  3. Verifies that the actual hostnames differ and contain non-ASCII characters
//
// This is a conservative detector: it only flags obvious homograph attempts where the core structure
// matches after normalizing confusable characters. The severity is later assessed based on how many
// confusable characters are actually used.
//
// Classic example: Using Cyrillic 'х' (U+0445) instead of Latin 'x' in a domain name.
// A single confusable character in an otherwise ASCII domain is flagged as Medium threat.
// Multiple confusable characters or combined with other attack vectors raise the threat to High/Critical.
//
// Parameters:
//   - host: The potentially suspicious hostname
//   - legit: The legitimate hostname being impersonated
//
// Returns true if the hostname appears to be a homograph attack against the legitimate domain.
func looksLikeConfusableHomograph(host, legit string) bool {
	normalizedHost := normalizeConfusables(host)
	normalizedLegit := normalizeConfusables(legit)
	if normalizedHost != normalizedLegit {
		return false
	}

	// Keep this strict to avoid flagging regular ASCII domains.
	return host != legit && containsNonASCII(host)
}

// normalizeConfusables converts confusable Unicode characters to their ASCII equivalents.
// This function maps Cyrillic, Greek, and other lookalike characters to standard Latin letters
// to enable homograph attack detection.
//
// Supported character families:
//   - Cyrillic characters (а, е, о, х, м, etc.)
//   - Greek characters (α, ρ, χ, etc.)
//   - Special Latin variants (ʟ)
//
// The normalization is case-insensitive and preserves unmapped characters as-is.
//
// Parameters:
//   - s: The string to normalize
//
// Returns the normalized string with confusable characters replaced by ASCII equivalents.
func normalizeConfusables(s string) string {
	var out []rune
	for _, r := range strings.ToLower(s) {
		if mapped, ok := confusableRuneDatabase[r]; ok {
			out = append(out, mapped)
			continue
		}
		out = append(out, r)
	}
	return string(out)
}

// containsNonASCII checks if a string contains any non-ASCII characters.
// This is used to identify potential homograph attacks that rely on Unicode characters
// to impersonate ASCII domains.
//
// Parameters:
//   - s: The string to check
//
// Returns true if the string contains at least one character with a Unicode codepoint > 127 (non-ASCII).
func containsNonASCII(s string) bool {
	for _, r := range s {
		if r > utf8.RuneSelf {
			return true
		}
	}
	return false
}

// hasSameSuffix checks if two hostnames share the same domain suffix (TLD and parent domain).
// This is used to ensure phishing comparisons are between domains with the same root
// (e.g., both .com, both .co.uk) to reduce false positives.
//
// Comparison method:
//  1. Splits both hostnames by dots
//  2. Compares the rightmost (TLD) segments
//  3. Returns true only if TLDs match exactly
//
// Examples:
//   - "gogle.com" and "google.com" -> true (both .com)
//   - "gogle.co.uk" and "google.com" -> false (different TLDs)
//
// Parameters:
//   - host: The potentially suspicious hostname
//   - legit: The legitimate hostname to compare against
//
// Returns true if both hostnames share the same TLD suffix.
func hasSameSuffix(host, legit string) bool {
	hostParts := strings.Split(host, ".")
	legitParts := strings.Split(legit, ".")
	if len(hostParts) < 2 || len(legitParts) < 2 {
		return false
	}
	return hostParts[len(hostParts)-1] == legitParts[len(legitParts)-1]
}

// isTranspositionVariant detects if a hostname is a variant of a legitimate domain
// where exactly two adjacent characters have been transposed (swapped).
// This detects a specific typo-squatting technique exploiting such common mistakes.
//
// Detection method:
//  1. Requires both strings to be exactly the same length
//  2. Finds the first position where characters differ
//  3. Checks if transposing two adjacent characters at that position makes strings identical
//  4. Ensures the rest of the string matches perfectly
//
// Examples:
//   - "goolge.com" is a transposition of "google.com" (o and g swapped position)
//   - "gogle.com" returns false (characters deleted, not transposed)
//
// Parameters:
//   - host: The potentially suspicious hostname
//   - legit: The legitimate hostname to compare againstr in an otherwise ASCII domain is flagged as Medium threat.
// Multiple confusable characters or
//
// Returns true if the hostname is exactly one adjacent-character transposition away from the legitimate domain.
func isTranspositionVariant(host, legit string) bool {
	if len(host) != len(legit) {
		return false
	}

	if host == legit {
		return false
	}

	for i := 0; i < len(host)-1; i++ {
		if host[i] != legit[i] {
			return host[i] == legit[i+1] && host[i+1] == legit[i] && host[i+2:] == legit[i+2:]
		}
	}

	return false
}

// isSingleEditDistance checks if two strings differ by exactly one edit operation (Levenshtein distance of 1).
// A single edit includes: one character insertion, one character deletion, or one character replacement.
// This detects common typo-squatting domains where a single character mistake was intentional.
//
// Algorithm:
//  1. Rejects identical strings (distance 0)
//  2. Rejects strings differing by more than one character in length
//  3. Uses a two-pointer approach to track position in both strings
//  4. On first mismatch, selects the appropriate edit operation (insert/delete/replace)
//  5. Counts total edits and rejects if more than one
//
// Examples:
//   - "googie.com" is 1 edit from "google.com" (replacement: l→i)
//   - "gogle.com" is 1 edit from "google.com" (deletion: o removed)
//   - "googlee.com" is 1 edit from "google.com" (insertion: extra e)
//   - "goolge.com" returns false (adjacent transposition requires 2 edits here)
//
// Parameters:
//   - a: First string
//   - b: Second string
//
// Returns true if the strings differ by exactly one edit operation.
func isSingleEditDistance(a, b string) bool {
	if a == b {
		return false
	}

	la := len(a)
	lb := len(b)
	if absInt(la-lb) > 1 {
		return false
	}

	i, j := 0, 0
	edits := 0

	for i < la && j < lb {
		if a[i] == b[j] {
			i++
			j++
			continue
		}

		edits++
		if edits > 1 {
			return false
		}

		if la > lb {
			i++
		} else if lb > la {
			j++
		} else {
			i++
			j++
		}
	}

	if i < la || j < lb {
		edits++
	}

	return edits == 1
}

// matchesReplacementVariant detects if a hostname matches a legitimate domain with common letter
// replacements applied. These replacements represent phishing techniques where specific characters
// are systematically replaced with lookalikes (e.g., 'm' replaced with 'rn', 'x' replaced with 'kz').
//
// Detection method:
//  1. Extracts the first label (subdomain) from both hostnames
//  2. Generates all possible replacement variants of the legitimate label
//  3. Reconstructs full domain names with each variant
//  4. Checks if any variant matches the suspicious hostname
//
// Supported replacements include:
//   - "m" → "rn", "nn" (looks like m when rendered)
//   - "x" → "kz"
//   - "l" → "1", "i" (number 1, lowercase i)
//   - "o" → "0" (number 0)
//   - And many others defined in the letter replacement database
//
// Parameters:
//   - host: The potentially suspicious hostname
//   - legit: The legitimate hostname to compare against
//   - replacements: Map of character→[replacements] for known phishing tricks
//
// Returns true if the hostname matches a replacement variant of the legitimate domain.
func matchesReplacementVariant(host, legit string, replacements map[string][]string) bool {
	hostParts := strings.Split(host, ".")
	legitParts := strings.Split(legit, ".")
	if len(hostParts) < 2 || len(legitParts) < 2 {
		return false
	}
	if len(hostParts) != len(legitParts) {
		return false
	}

	// Check each non-TLD label so multi-label legitimate domains such as
	// aws.amazon.com and cloud.google.com are also covered.
	for labelIndex := 0; labelIndex < len(legitParts)-1; labelIndex++ {
		hostLabel := hostParts[labelIndex]
		legitLabel := legitParts[labelIndex]
		if hostLabel == legitLabel {
			continue
		}

		variants := generateReplacementVariants(legitLabel, replacements)
		for _, v := range variants {
			candidateParts := append([]string(nil), legitParts...)
			candidateParts[labelIndex] = v
			if strings.Join(candidateParts, ".") == host {
				return true
			}
		}
	}

	return false
}

// generateReplacementVariants creates all possible letter-replacement variants of a domain label.
// This generates the lookalike variations that attackers create using popular character replacements.
//
// Algorithm:
//  1. Starts with the original label as a base variant
//  2. For each character in the replacements map:
//     - If that character exists in the label
//     - Generates a variant replacing all occurrences with each replacement option
//  3. Deduplicates variants to prevent duplicates
//  4. Returns all unique variants
//
// Example: For label "google" with m→rn replacement:
//   - Input: "mail" with m→rn would produce variants like "rnail"
//
// Parameters:
//   - label: The domain label to generate variants for (e.g., "google")
//   - replacements: Map of character→[replacements] containing the replacement strategy
//
// Returns a slice of all unique replacement variants of the original label.
func generateReplacementVariants(label string, replacements map[string][]string) []string {
	result := map[string]struct{}{}
	result[label] = struct{}{}

	for original, alts := range replacements {
		for _, alt := range alts {
			if !strings.Contains(label, original) {
				continue
			}
			candidate := strings.ReplaceAll(label, original, alt)
			result[candidate] = struct{}{}
		}
	}

	out := make([]string, 0, len(result))
	for k := range result {
		out = append(out, k)
	}
	return out
}

// uniqueStrings removes duplicate strings from a slice while preserving order.
// Used to deduplicate phishing pattern detection results.
//
// Parameters:
//   - in: Input slice of strings that may contain duplicates
//
// Returns a new slice containing only unique strings with duplicates removed.
func uniqueStrings(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// countConfusableCharacters counts how many confusable Unicode characters are present in a string.
// Used to assess the severity of homograph attacks based on character prevalence.
//
// Parameters:
//   - s: The string to analyze
//
// Returns the count of characters that exist in the confusable character map.
func countConfusableCharacters(s string) int {
	count := 0
	for _, r := range s {
		if _, ok := confusableRuneDatabase[r]; ok {
			count++
		}
	}
	return count
}

// absInt returns the absolute value of an integer.
// Used in edit distance calculations to handle both positive and negative differences.
//
// Parameters:
//   - x: The integer value
//
// Returns the absolute value of x (always non-negative).
func absInt(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// credentialParameterDatabase lists query parameter names that carry an actual
// secret. A URL containing any of these leaks the secret into browser history,
// proxy logs, and the Referer header - and is a hallmark of phishing forms that
// submit harvested credentials over GET.
var credentialParameterDatabase = []string{
	"password", "passwd", "pwd", "pass", "passphrase", "userpassword", "userpass",
	"secret", "clientsecret", "appsecret", "privatekey", "credentials", "creds",
}

// sensitiveParameterDatabase lists query parameter names that carry authentication
// or payment material. Exposing them in a URL is dangerous on its own and is a
// common pattern in phishing links that pre-authenticate a victim session.
var sensitiveParameterDatabase = []string{
	"token", "accesstoken", "idtoken", "refreshtoken", "authtoken", "auth",
	"authorization", "apikey", "apitoken", "session", "sessionid", "jsessionid",
	"phpsessid", "sid", "otp", "mfa", "2fa", "pin", "code", "cardnumber",
	"creditcard", "cvv", "cvc", "iban", "ssn",
}

// identityParameterDatabase lists parameter names used by phishing kits to
// pre-fill the victim identity, so the landing page can greet the target by name
// and look legitimate. On their own they are not secrets, but a link that carries
// the recipient identity is a strong phishing indicator.
var identityParameterDatabase = []string{
	"email", "mail", "emailaddress", "username", "user", "usr", "userid",
	"login", "account", "accountid", "customerid",
}

// redirectParameterDatabase lists parameter names commonly used to carry a
// redirection target. When such a parameter points at an external host, the link
// can be used to bounce a victim from a trusted-looking URL to attacker content.
var redirectParameterDatabase = []string{
	"redirect", "redirecturi", "redirecturl", "returnurl", "returnto", "return",
	"continue", "next", "goto", "dest", "destination", "target", "callback",
	"forward", "url", "uri", "link", "out",
}

// dangerousSchemeDatabase lists URL schemes that must never appear inside a
// parameter value. They allow direct script execution or inline payload delivery
// when the value is reflected into the page.
var dangerousSchemeDatabase = []string{
	"javascript:", "data:", "vbscript:", "file:",
}

// phishingPathKeywordDatabase lists path fragments heavily used by phishing kits
// to make a URL look like an official account operation.
var phishingPathKeywordDatabase = []string{
	"secure", "verify", "verification", "confirm", "validate", "update",
	"unlock", "recover", "restore", "suspended", "signin", "webscr",
}

// Structural limits above which a URL is considered abnormally complex.
// Legitimate application URLs rarely exceed them, while phishing links padded
// with tracking and obfuscation data routinely do.
const (
	maxReasonableQueryLength    = 512 // characters in the raw query string
	maxReasonableParameterCount = 12  // distinct query parameters
	minBrandKeywordLength       = 5   // shortest brand name safe to match in a path
)

// redactedPlaceholder replaces every secret rendered into the reported URL.
const redactedPlaceholder = "[REDACTED]"

// extractRequestURL safely retrieves the final request URL from the test parameters.
// The response chain is validated step by step, because a response produced by a
// failed or synthetic request may carry no request or no URL at all.
//
// Parameters:
//   - params: ResponseTestParams containing the HTTP response to analyze
//
// Returns:
//   - *url.URL: The request URL, or nil when it cannot be determined
func extractRequestURL(params ResponseTestParams) *url.URL {
	if params.Response == nil || params.Response.Request == nil {
		return nil
	}
	return params.Response.Request.URL
}

// analyzeURLParameters performs the full phishing analysis of a URL.
//
// Analysis steps:
//  1. Inspect the userinfo section for credentials embedded directly in the URL
//  2. Classify every query parameter name against the credential, sensitive,
//     identity and redirect databases
//  3. Inspect every parameter value for external redirect targets, base64 encoded
//     URLs or e-mail addresses, and dangerous schemes
//  4. Look for popular brand keywords in the path or query while the hostname is
//     unrelated to that brand
//  5. Collect structural indicators (IP literal host, oversized query, phishing
//     path keywords)
//
// Parameter values are deliberately never stored in the returned metadata; only
// names, counts and a redacted URL are reported.
//
// Parameters:
//   - target: The URL to analyze
//
// Returns a map containing analysis metadata:
//   - url: The URL with every secret value replaced by [REDACTED]
//   - is_suspicious: Boolean indicating whether any phishing indicator was found
//   - embedded_credentials: Boolean indicating userinfo credentials in the URL
//   - credential_values_present: Boolean indicating a credential parameter carries a value
//   - parameter_count: Number of distinct query parameters
//   - analyzed_parameters: Names of all query parameters
//   - credential_parameters: Parameter names carrying secrets
//   - sensitive_parameters: Parameter names carrying authentication or payment data
//   - identity_parameters: Parameter names carrying the victim identity
//   - external_redirect_parameters: Redirect parameters pointing to another host
//   - encoded_payload_parameters: Parameters hiding a base64 encoded URL or e-mail
//   - dangerous_scheme_parameters: Parameters carrying javascript:, data: and similar
//   - brand_keywords_in_url: Popular brand names found outside the hostname
//   - structural_indicators: Structural anomalies of the URL
//   - detected_patterns: Human-readable list of all detected indicators
func analyzeURLParameters(target *url.URL) map[string]any {
	host := strings.ToLower(strings.TrimSuffix(target.Hostname(), "."))
	query := target.Query()

	analysis := map[string]any{
		"url":                          buildRedactedURL(target),
		"is_suspicious":                false,
		"embedded_credentials":         false,
		"credential_values_present":    false,
		"parameter_count":              len(query),
		"analyzed_parameters":          []string{},
		"credential_parameters":        []string{},
		"sensitive_parameters":         []string{},
		"identity_parameters":          []string{},
		"external_redirect_parameters": []string{},
		"encoded_payload_parameters":   []string{},
		"dangerous_scheme_parameters":  []string{},
		"brand_keywords_in_url":        []string{},
		"structural_indicators":        []string{},
		"detected_patterns":            []string{},
	}

	names := []string{}
	credentials := []string{}
	sensitive := []string{}
	identity := []string{}
	externalRedirects := []string{}
	encodedPayloads := []string{}
	dangerousSchemes := []string{}
	patterns := []string{}
	credentialValuePresent := false

	// Userinfo credentials are the most explicit form of credential exposure and
	// are additionally used to hide the real host behind an "@" in the URL.
	if target.User != nil && target.User.Username() != "" {
		analysis["embedded_credentials"] = true
		patterns = append(patterns, "credentials embedded in the URL userinfo")
		if password, hasPassword := target.User.Password(); hasPassword && password != "" {
			credentialValuePresent = true
		}
	}

	for _, name := range sortedParameterNames(query) {
		names = append(names, name)

		if keyword, matched := matchesParameterDatabase(name, credentialParameterDatabase); matched {
			credentials = append(credentials, name)
			if hasNonEmptyValue(query[name]) {
				credentialValuePresent = true
			}
			patterns = append(patterns, fmt.Sprintf("credential parameter %q (matches %q)", name, keyword))
		} else if keyword, matched := matchesParameterDatabase(name, sensitiveParameterDatabase); matched {
			sensitive = append(sensitive, name)
			patterns = append(patterns, fmt.Sprintf("sensitive parameter %q (matches %q)", name, keyword))
		} else if _, matched := matchesParameterDatabase(name, identityParameterDatabase); matched {
			identity = append(identity, name)
			patterns = append(patterns, fmt.Sprintf("victim identity parameter %q", name))
		}

		_, isRedirectParameter := matchesParameterDatabase(name, redirectParameterDatabase)

		for _, value := range query[name] {
			if usesDangerousScheme(value) {
				dangerousSchemes = append(dangerousSchemes, name)
				patterns = append(patterns, fmt.Sprintf("parameter %q carries a dangerous scheme", name))
			}

			if isRedirectParameter && isExternalRedirectTarget(host, value) {
				externalRedirects = append(externalRedirects, name)
				patterns = append(patterns, fmt.Sprintf("redirect parameter %q points to an external host", name))
			}

			if payload, hidden := decodeHiddenPayload(value); hidden {
				encodedPayloads = append(encodedPayloads, name)
				patterns = append(patterns, fmt.Sprintf("parameter %q hides a base64 encoded %s", name, payload))
			}
		}
	}

	brands := detectBrandKeywordsOutsideHost(host, target)
	for _, brand := range brands {
		patterns = append(patterns, fmt.Sprintf("brand keyword %q used outside the hostname", brand))
	}

	structural := detectStructuralIndicators(host, target, len(query))
	patterns = append(patterns, structural...)

	analysis["credential_values_present"] = credentialValuePresent
	analysis["analyzed_parameters"] = names
	analysis["credential_parameters"] = uniqueStrings(credentials)
	analysis["sensitive_parameters"] = uniqueStrings(sensitive)
	analysis["identity_parameters"] = uniqueStrings(identity)
	analysis["external_redirect_parameters"] = uniqueStrings(externalRedirects)
	analysis["encoded_payload_parameters"] = uniqueStrings(encodedPayloads)
	analysis["dangerous_scheme_parameters"] = uniqueStrings(dangerousSchemes)
	analysis["brand_keywords_in_url"] = brands
	analysis["structural_indicators"] = structural
	analysis["detected_patterns"] = uniqueStrings(patterns)
	analysis["is_suspicious"] = len(patterns) > 0

	return analysis
}

// evaluateURLParameterThreatLevel determines the security threat classification
// based on the indicators collected by analyzeURLParameters.
//
// Threat level assignment logic:
//   - ThreatLevel.Critical: Credentials are present in the URL (userinfo or a
//     credential parameter carrying a value), or a parameter carries a dangerous
//     scheme, or three or more High level indicators are combined
//   - ThreatLevel.High: Empty credential parameters, sensitive data parameters,
//     external redirect targets or base64 hidden payloads
//   - ThreatLevel.High: Two or more weak indicators combined (victim identity,
//     brand keyword outside the hostname, IP literal host), or a brand keyword
//     reinforced by a phishing-style path
//   - ThreatLevel.Medium: A single weak indicator
//   - ThreatLevel.Low: Only structural anomalies such as an oversized query string
//   - ThreatLevel.None: No indicators detected
//
// Parameters:
//   - metadata: Analysis metadata map produced by analyzeURLParameters
//
// Returns the assigned ThreatLevel based on the indicators and their combination.
func evaluateURLParameterThreatLevel(metadata map[string]any) ThreatLevel {
	isSuspicious, _ := metadata["is_suspicious"].(bool)
	if !isSuspicious {
		return None
	}

	embedded, _ := metadata["embedded_credentials"].(bool)
	credentialValues, _ := metadata["credential_values_present"].(bool)
	credentials, _ := metadata["credential_parameters"].([]string)
	sensitive, _ := metadata["sensitive_parameters"].([]string)
	identity, _ := metadata["identity_parameters"].([]string)
	redirects, _ := metadata["external_redirect_parameters"].([]string)
	encoded, _ := metadata["encoded_payload_parameters"].([]string)
	schemes, _ := metadata["dangerous_scheme_parameters"].([]string)
	brands, _ := metadata["brand_keywords_in_url"].([]string)
	structural, _ := metadata["structural_indicators"].([]string)

	// Credentials travelling inside the URL or an executable scheme in a value
	// are unambiguous - no additional confirmation is required.
	if (embedded && credentialValues) || (len(credentials) > 0 && credentialValues) || len(schemes) > 0 {
		return Critical
	}

	highIndicators := len(credentials) + len(sensitive) + len(redirects) + len(encoded)
	if embedded {
		highIndicators++
	}

	// Several independent high severity indicators in a single URL describe a
	// fully assembled phishing link rather than a sloppy application.
	if highIndicators >= 3 {
		return Critical
	}

	if highIndicators > 0 {
		return High
	}

	// Weak indicators are individually inconclusive, but a link that pre-fills the
	// victim identity, borrows a brand name and uses an account-operation path at
	// the same time is the standard layout of a phishing landing page.
	weakIndicators := 0
	if len(identity) > 0 {
		weakIndicators++
	}
	if len(brands) > 0 {
		weakIndicators++
	}
	if containsStructuralIndicator(structural, "IP literal") {
		weakIndicators++
	}
	hasPhishingPath := containsStructuralIndicator(structural, "path keyword")

	// A phishing path keyword on its own is far too common in legitimate
	// applications to raise the level, so it only reinforces a brand mismatch.
	if weakIndicators >= 2 || (len(brands) > 0 && hasPhishingPath) {
		return High
	}

	if weakIndicators == 1 {
		return Medium
	}

	if len(structural) > 0 {
		return Low
	}

	return None
}

// generateURLParameterDescription creates a human-readable summary of the analysis.
// The description names the indicators and the affected parameters so the finding
// is actionable, but never reproduces a parameter value.
//
// Parameters:
//   - metadata: Analysis results map produced by analyzeURLParameters
//
// Returns a detailed, user-friendly description suitable for security reports.
func generateURLParameterDescription(metadata map[string]any) string {
	isSuspicious, _ := metadata["is_suspicious"].(bool)
	if !isSuspicious {
		count, _ := metadata["parameter_count"].(int)
		if count == 0 {
			return "URL carries no query parameters and no phishing indicators were detected"
		}
		return fmt.Sprintf("No phishing indicators detected in the %d URL parameter(s)", count)
	}

	sections := []string{}

	if embedded, _ := metadata["embedded_credentials"].(bool); embedded {
		sections = append(sections, "credentials are embedded directly in the URL")
	}
	sections = appendParameterSection(sections, metadata, "credential_parameters", "credential parameter(s)")
	sections = appendParameterSection(sections, metadata, "sensitive_parameters", "sensitive data parameter(s)")
	sections = appendParameterSection(sections, metadata, "dangerous_scheme_parameters", "parameter(s) with a dangerous scheme")
	sections = appendParameterSection(sections, metadata, "external_redirect_parameters", "external redirect parameter(s)")
	sections = appendParameterSection(sections, metadata, "encoded_payload_parameters", "parameter(s) hiding encoded data")
	sections = appendParameterSection(sections, metadata, "identity_parameters", "victim identity parameter(s)")

	if brands, _ := metadata["brand_keywords_in_url"].([]string); len(brands) > 0 {
		sections = append(sections, fmt.Sprintf("brand keyword(s) used outside the hostname: %s", strings.Join(brands, ", ")))
	}

	if structural, _ := metadata["structural_indicators"].([]string); len(structural) > 0 {
		sections = append(sections, strings.Join(structural, "; "))
	}

	return fmt.Sprintf(
		"Suspicious URL detected: %s. Analyzed URL: %s",
		strings.Join(sections, "; "),
		metadata["url"],
	)
}

// appendParameterSection appends a description fragment for one metadata category,
// but only when that category actually contains parameters. It keeps the
// description generator free of repeated emptiness checks.
//
// Parameters:
//   - sections: Description fragments collected so far
//   - metadata: Analysis results map produced by analyzeURLParameters
//   - key: Metadata key holding the parameter names
//   - label: Human-readable label describing the category
//
// Returns the section list with the new fragment appended when applicable.
func appendParameterSection(sections []string, metadata map[string]any, key string, label string) []string {
	values, _ := metadata[key].([]string)
	if len(values) == 0 {
		return sections
	}
	return append(sections, fmt.Sprintf("%s: %s", label, strings.Join(values, ", ")))
}

// sortedParameterNames returns the query parameter names in a stable alphabetical
// order. Go randomizes map iteration, so sorting keeps the reported metadata and
// descriptions identical between runs on the same URL.
//
// Parameters:
//   - query: Parsed query parameters
//
// Returns the parameter names sorted alphabetically.
func sortedParameterNames(query url.Values) []string {
	names := make([]string, 0, len(query))
	for name := range query {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// matchesParameterDatabase checks whether a parameter name matches any entry of a
// parameter database. Names are normalized first, so "user_password", "userPassword"
// and "user.password" are all recognized as the same parameter.
//
// Matching rules:
//   - Entries of at least four characters also match as a substring, catching
//     prefixed and suffixed variants such as "login_token" or "tokenValue"
//   - Shorter entries must match exactly, which prevents noise from generic names
//     (for example "sid" must not match "considered")
//
// Parameters:
//   - name: The query parameter name to classify
//   - database: The parameter name database to match against
//
// Returns:
//   - string: The matched database entry, empty when nothing matched
//   - bool: true when the parameter name matched the database
func matchesParameterDatabase(name string, database []string) (string, bool) {
	normalized := normalizeParameterName(name)
	if normalized == "" {
		return "", false
	}

	for _, entry := range database {
		if normalized == entry {
			return entry, true
		}
		if len(entry) >= 4 && strings.Contains(normalized, entry) {
			return entry, true
		}
	}

	return "", false
}

// normalizeParameterName lowercases a parameter name and removes the separators
// commonly used to compose parameter names, so that different spellings of the
// same concept collapse into a single comparable form.
//
// Parameters:
//   - name: The raw query parameter name
//
// Returns the normalized parameter name.
func normalizeParameterName(name string) string {
	replacer := strings.NewReplacer("_", "", "-", "", ".", "", "[", "", "]", "", " ", "")
	return replacer.Replace(strings.ToLower(strings.TrimSpace(name)))
}

// hasNonEmptyValue reports whether at least one of the values assigned to a
// parameter is non-empty. An empty credential parameter still indicates a bad
// URL design, but a filled one means a live secret is travelling in the URL.
//
// Parameters:
//   - values: All values assigned to a single parameter
//
// Returns true when any value carries content.
func hasNonEmptyValue(values []string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return true
		}
	}
	return false
}

// usesDangerousScheme reports whether a parameter value starts with a scheme that
// allows script execution or inline payload delivery. Such values are typically
// reflected into links or redirects and turn the page into an attack vector.
//
// Parameters:
//   - value: The parameter value to inspect
//
// Returns true when the value starts with a dangerous scheme.
func usesDangerousScheme(value string) bool {
	normalized := strings.ToLower(strings.TrimSpace(value))
	normalized = strings.NewReplacer("\t", "", "\n", "", "\r", "").Replace(normalized)

	for _, scheme := range dangerousSchemeDatabase {
		if strings.HasPrefix(normalized, scheme) {
			return true
		}
	}
	return false
}

// isExternalRedirectTarget reports whether a redirect parameter value points to a
// host different from the one being scanned. Same-site redirects are normal
// application behaviour, cross-site ones allow a trusted URL to deliver a victim
// to attacker controlled content.
//
// Protocol-relative values ("//evil.tld/path") are resolved as absolute URLs,
// because browsers treat them as such while they are easy to overlook manually.
//
// Parameters:
//   - currentHost: The hostname of the scanned URL
//   - value: The redirect parameter value
//
// Returns true when the value targets a different host.
func isExternalRedirectTarget(currentHost string, value string) bool {
	candidate := strings.TrimSpace(value)
	if strings.HasPrefix(candidate, "//") {
		candidate = "http:" + candidate
	}

	parsed, err := url.Parse(candidate)
	if err != nil || parsed.Host == "" {
		return false
	}

	targetHost := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	if targetHost == "" || targetHost == currentHost {
		return false
	}

	// Redirects between a host and its own subdomains stay inside the same site.
	return !strings.HasSuffix(targetHost, "."+currentHost) && !strings.HasSuffix(currentHost, "."+targetHost)
}

// decodeHiddenPayload detects base64 encoded content inside a parameter value.
// Phishing links routinely encode the redirect target or the recipient e-mail
// address to survive naive link scanners and to hide the destination from the
// victim ("?e=dmljdGltQGNvcnAudGxk").
//
// Only decoded content that is a URL or an e-mail address is reported, which
// keeps ordinary opaque identifiers and encoded application state out of the
// findings.
//
// Parameters:
//   - value: The parameter value to inspect
//
// Returns:
//   - string: Description of what was hidden ("URL" or "e-mail address")
//   - bool: true when an encoded URL or e-mail address was found
func decodeHiddenPayload(value string) (string, bool) {
	decoded, ok := decodeBase64Candidate(value)
	if !ok {
		return "", false
	}

	lowered := strings.ToLower(decoded)
	if strings.Contains(lowered, "http://") || strings.Contains(lowered, "https://") || strings.HasPrefix(lowered, "//") {
		return "URL", true
	}

	if looksLikeEmailAddress(decoded) {
		return "e-mail address", true
	}

	return "", false
}

// decodeBase64Candidate attempts to decode a parameter value as base64 using the
// standard and URL-safe alphabets, in both padded and unpadded form.
//
// Very short values are ignored because they decode to noise by coincidence, and
// results that are not mostly printable text are rejected, since binary output
// means the value simply was not base64 in the first place.
//
// Parameters:
//   - value: The parameter value to decode
//
// Returns:
//   - string: The decoded text
//   - bool: true when the value decoded to printable text
func decodeBase64Candidate(value string) (string, bool) {
	trimmed := strings.TrimSpace(value)
	if len(trimmed) < 16 || len(trimmed) > 2048 {
		return "", false
	}

	if strings.ContainsAny(trimmed, " \t\r\n") {
		return "", false
	}

	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}

	for _, encoding := range encodings {
		decoded, err := encoding.DecodeString(trimmed)
		if err != nil {
			continue
		}
		if !isMostlyPrintable(string(decoded)) {
			continue
		}
		return string(decoded), true
	}

	return "", false
}

// isMostlyPrintable reports whether a decoded string consists predominantly of
// printable ASCII characters. It separates genuine text from byte sequences that
// merely happen to be valid base64.
//
// Parameters:
//   - s: The decoded string to evaluate
//
// Returns true when at least 90% of the characters are printable ASCII.
func isMostlyPrintable(s string) bool {
	if s == "" {
		return false
	}

	printable := 0
	for _, r := range s {
		if r >= 0x20 && r <= 0x7E {
			printable++
		}
	}

	return printable*10 >= len(s)*9
}

// looksLikeEmailAddress performs a lightweight check for an e-mail address.
// A full RFC compliant validation is unnecessary here - the goal is only to
// recognize that a decoded value identifies a specific victim.
//
// Parameters:
//   - value: The value to inspect
//
// Returns true when the value has the shape of an e-mail address.
func looksLikeEmailAddress(value string) bool {
	candidate := strings.TrimSpace(value)
	if strings.ContainsAny(candidate, " \t\r\n") {
		return false
	}

	at := strings.Index(candidate, "@")
	if at <= 0 || at == len(candidate)-1 || strings.Count(candidate, "@") != 1 {
		return false
	}

	domain := candidate[at+1:]
	dot := strings.LastIndex(domain, ".")

	return dot > 0 && dot < len(domain)-1
}

// detectBrandKeywordsOutsideHost finds popular brand names placed in the path or
// query of a URL whose hostname has nothing to do with that brand. This is the
// cheapest and most common phishing layout: an unrelated compromised host serving
// a branded path such as /secure/paypal/login.
//
// The check reuses the popular domain dataset of the hostname analysis, skips
// short brand names that would match ordinary words, and requires the keyword to
// appear as a standalone token rather than as part of a longer word.
//
// Parameters:
//   - host: The hostname of the scanned URL
//   - target: The URL to inspect
//
// Returns the sorted list of brand keywords used outside the hostname.
func detectBrandKeywordsOutsideHost(host string, target *url.URL) []string {
	haystack := strings.ToLower(target.EscapedPath() + "?" + target.RawQuery)
	found := []string{}

	for brand := range popularDomainDatabase {
		if len(brand) < minBrandKeywordLength {
			continue
		}
		if strings.Contains(host, brand) {
			continue
		}
		if containsStandaloneToken(haystack, brand) {
			found = append(found, brand)
		}
	}

	sort.Strings(found)
	return found
}

// containsStandaloneToken reports whether a keyword appears in a string delimited
// by non-alphanumeric characters. It prevents matches inside unrelated longer
// words, so "google" is not reported for a path containing "googleapis".
//
// Parameters:
//   - haystack: The lowercased string to search
//   - token: The keyword to look for
//
// Returns true when the keyword appears as a standalone token.
func containsStandaloneToken(haystack string, token string) bool {
	offset := 0
	for {
		index := strings.Index(haystack[offset:], token)
		if index < 0 {
			return false
		}

		start := offset + index
		end := start + len(token)

		if !isAlphanumericAt(haystack, start-1) && !isAlphanumericAt(haystack, end) {
			return true
		}

		offset = start + 1
		if offset >= len(haystack) {
			return false
		}
	}
}

// isAlphanumericAt reports whether the byte at a given index is a letter or digit.
// Positions outside the string are treated as delimiters, so a token at the very
// beginning or end of the string still counts as standalone.
//
// Parameters:
//   - s: The string to inspect
//   - index: The byte position to check
//
// Returns true when the position holds an ASCII letter or digit.
func isAlphanumericAt(s string, index int) bool {
	if index < 0 || index >= len(s) {
		return false
	}

	c := s[index]
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// detectStructuralIndicators collects anomalies in the overall shape of the URL.
// None of them proves phishing on its own, but they describe links that were
// assembled by a kit rather than by an application.
//
// Detected anomalies:
//   - IP literal used instead of a hostname
//   - Phishing-style keywords in the path (secure, verify, confirm, ...)
//   - Query string longer than maxReasonableQueryLength characters
//   - More than maxReasonableParameterCount distinct parameters
//
// Parameters:
//   - host: The hostname of the scanned URL
//   - target: The URL to inspect
//   - parameterCount: Number of distinct query parameters
//
// Returns the list of structural indicators found.
func detectStructuralIndicators(host string, target *url.URL, parameterCount int) []string {
	indicators := []string{}

	if net.ParseIP(host) != nil {
		indicators = append(indicators, "IP literal used instead of a hostname")
	}

	keywords := []string{}
	path := strings.ToLower(target.EscapedPath())
	for _, keyword := range phishingPathKeywordDatabase {
		if containsStandaloneToken(path, keyword) {
			keywords = append(keywords, keyword)
		}
	}
	if len(keywords) > 0 {
		indicators = append(indicators, fmt.Sprintf("phishing-style path keyword(s): %s", strings.Join(keywords, ", ")))
	}

	if len(target.RawQuery) > maxReasonableQueryLength {
		indicators = append(indicators, fmt.Sprintf("query string is unusually long (%d characters)", len(target.RawQuery)))
	}

	if parameterCount > maxReasonableParameterCount {
		indicators = append(indicators, fmt.Sprintf("unusually many query parameters (%d)", parameterCount))
	}

	return indicators
}

// containsStructuralIndicator reports whether any structural indicator contains a
// given fragment. It lets the threat evaluation react to a specific indicator
// without duplicating its full wording.
//
// Parameters:
//   - indicators: The structural indicators collected during analysis
//   - fragment: The fragment to look for
//
// Returns true when any indicator contains the fragment.
func containsStructuralIndicator(indicators []string, fragment string) bool {
	for _, indicator := range indicators {
		if strings.Contains(indicator, fragment) {
			return true
		}
	}
	return false
}

// buildRedactedURL renders the analyzed URL with every secret removed, so the
// finding can be stored and displayed without leaking the credentials it reports.
//
// Redaction rules:
//   - Userinfo is replaced entirely by the redaction placeholder
//   - Values of credential and sensitive parameters are replaced by the placeholder
//   - All other parameter values are preserved for context
//
// Parameters:
//   - target: The URL to render
//
// Returns the redacted URL string.
func buildRedactedURL(target *url.URL) string {
	redacted := *target
	redacted.User = nil
	redacted.RawQuery = buildRedactedQuery(target)

	rendered := redacted.String()
	if target.User != nil {
		if separator := strings.Index(rendered, "//"); separator >= 0 {
			insert := separator + len("//")
			rendered = rendered[:insert] + redactedPlaceholder + "@" + rendered[insert:]
		}
	}

	return rendered
}

// buildRedactedQuery renders the query string with the values of credential and
// sensitive parameters replaced by the redaction placeholder. Names and remaining
// values are escaped normally, while the placeholder is written literally so the
// report stays readable.
//
// Parameters:
//   - target: The URL whose query string is rendered
//
// Returns the redacted raw query string.
func buildRedactedQuery(target *url.URL) string {
	query := target.Query()
	if len(query) == 0 {
		return ""
	}

	pairs := []string{}
	for _, name := range sortedParameterNames(query) {
		_, isCredential := matchesParameterDatabase(name, credentialParameterDatabase)
		_, isSensitive := matchesParameterDatabase(name, sensitiveParameterDatabase)

		for _, value := range query[name] {
			if isCredential || isSensitive {
				pairs = append(pairs, url.QueryEscape(name)+"="+redactedPlaceholder)
				continue
			}
			pairs = append(pairs, url.QueryEscape(name)+"="+url.QueryEscape(value))
		}
	}

	return strings.Join(pairs, "&")
}
