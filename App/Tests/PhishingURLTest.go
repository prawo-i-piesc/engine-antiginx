// Package Tests provides security testing functionality for Engine-AntiGinx.
//
// # PhishingURLTest Module
//
// This module analyzes the target hostname for indicators of phishing-style
// domain impersonation, including typo-squatting and homograph-style tricks.
package Tests

import (
	"fmt"
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

// NewPhishingURLTest creates and returns a new ResponseTest instance for phishing domain detection.
// This test analyzes hostnames for indicators of phishing-style domain impersonation,
// including typo-squatting (deliberate misspellings), and homograph attacks
// (using confusable Unicode characters to impersonate legitimate domains).
//
// The test detects multiple attack vectors:
//   - Single-character typos (e.g., "gogle.com" instead of "google.com")
//   - Adjacent-character transpositions (e.g., "goolge.com")
//   - Popular letter replacements (e.g., "m" replaced with "rn", "x" with Cyrillic х)
//   - Homograph attacks using confusable Unicode characters (Cyrillic, Greek, etc.)
//
// Returns a configured ResponseTest ready for execution against HTTP responses.
// The test will return:
//   - ThreatLevel.None if the domain is legitimate or has no phishing indicators
//   - ThreatLevel.Medium if a single phishing pattern is detected
//   - ThreatLevel.High if multiple phishing patterns are detected or widespread homograph usage
//   - ThreatLevel.Critical if multiple phishing patterns combined with homograph characters
//
// Example:
//
//	phishingTest := NewPhishingURLTest()
//	result := phishingTest.Run(ResponseTestParams{Response: httpResponse})
//	if result.ThreatLevel != None {
//	    fmt.Printf("Phishing risk detected: %s\n", result.Description)
//	}
func NewPhishingURLTest() *ResponseTest {
	return &ResponseTest{
		Id:          "phishing-url",
		Name:        "Phishing Domain Impersonation Analysis",
		Description: "Analyzes the hostname for typo-squatting and homograph patterns that mimic popular domains",
		RunTest: func(params ResponseTestParams) TestResult {
			host := strings.ToLower(strings.TrimSuffix(params.Response.Request.URL.Hostname(), "."))
			if host == "" {
				return TestResult{
					Name:        "Phishing Domain Impersonation Analysis",
					Certainty:   100,
					ThreatLevel: Info,
					Metadata: map[string]any{
						"host": host,
					},
					Description: "Host is empty, phishing analysis could not be performed",
				}
			}

			analysis := analyzePhishingDomain(host)
			threat := evaluatePhishingThreatLevel(analysis)

			certainty := 95
			if !analysis["is_suspicious"].(bool) {
				certainty = 100
			}

			return TestResult{
				Name:        "Phishing Domain Impersonation Analysis",
				Certainty:   certainty,
				ThreatLevel: threat,
				Metadata:    analysis,
				Description: generatePhishingDescription(analysis),
			}
		},
	}
}

// analyzePhishingDomain performs comprehensive phishing analysis on a given hostname.
// It checks the hostname against a database of legitimate popular domains and applies
// multiple detection techniques to identify phishing attempts.
//
// Analysis steps:
//   1. First checks if the hostname is a known legitimate domain (early exit for safety)
//   2. Compares the hostname against database of legitimate domains using four detection vectors:
//      - Single edit distance (Levenshtein distance of 1)
//      - Adjacent character transpositions
//      - Popular character replacements (e.g., m→rn, x→х)
//      - Homograph attacks using confusable Unicode characters
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
//   1. Normalizes both hostnames using the confusable character map
//   2. Checks if normalized versions are identical
//   3. Verifies that the actual hostnames differ and contain non-ASCII characters
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
//   1. Splits both hostnames by dots
//   2. Compares the rightmost (TLD) segments
//   3. Returns true only if TLDs match exactly
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
//   1. Requires both strings to be exactly the same length
//   2. Finds the first position where characters differ
//   3. Checks if transposing two adjacent characters at that position makes strings identical
//   4. Ensures the rest of the string matches perfectly
//
// Examples:
//   - "goolge.com" is a transposition of "google.com" (o and g swapped position)
//   - "gogle.com" returns false (characters deleted, not transposed)
//
// Parameters:
//   - host: The potentially suspicious hostname
//   - legit: The legitimate hostname to compare against
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
//   1. Rejects identical strings (distance 0)
//   2. Rejects strings differing by more than one character in length
//   3. Uses a two-pointer approach to track position in both strings
//   4. On first mismatch, selects the appropriate edit operation (insert/delete/replace)
//   5. Counts total edits and rejects if more than one
//
// Examples:
//   - "googlе.com" is 1 edit from "googie.com" (replacement: l→i)
//   - "gogle.com" is 1 edit from "google.com" (deletion: o removed)
//   - "googlee.com" is 1 edit from "google.com" (insertion: extra e)
//   - "goglge.com" returns false (2+ edits needed)
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
// are systematically replaced with lookalikes (e.g., 'm' replaced with 'rn', 'x' replaced with Cyrillic 'х').
//
// Detection method:
//   1. Extracts the first label (subdomain) from both hostnames
//   2. Generates all possible replacement variants of the legitimate label
//   3. Reconstructs full domain names with each variant
//   4. Checks if any variant matches the suspicious hostname
//
// Supported replacements include:
//   - "m" → "rn", "nn" (looks like m when rendered)
//   - "x" → "kz", "х" (Cyrillic x)
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

	hostLabel := hostParts[0]
	legitLabel := legitParts[0]
	if hostLabel == legitLabel {
		return false
	}

	variants := generateReplacementVariants(legitLabel, replacements)
	for _, v := range variants {
		candidate := v + "." + strings.Join(legitParts[1:], ".")
		if candidate == host {
			return true
		}
	}

	return false
}

// generateReplacementVariants creates all possible letter-replacement variants of a domain label.
// This generates the lookalike variations that attackers create using popular character replacements.
//
// Algorithm:
//   1. Starts with the original label as a base variant
//   2. For each character in the replacements map:
//      - If that character exists in the label
//      - Generates a variant replacing all occurrences with each replacement option
//   3. Deduplicates variants to prevent duplicates
//   4. Returns all unique variants
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
