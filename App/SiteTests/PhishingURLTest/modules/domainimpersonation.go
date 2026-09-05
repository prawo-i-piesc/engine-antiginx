// Package modules holds the stage implementations of the Phishing URL Analysis test.
// It is used by its own core.go and nothing else.
package modules

import (
	"Engine-AntiGinx/App/SiteTests"
	"fmt"
	"strings"
	"unicode/utf8"
)

// DomainAnalyzer decides whether a hostname impersonates a known brand.
type DomainAnalyzer struct {
	Popular            map[string][]string
	LetterReplacements map[string][]string
	Confusables        map[rune]rune
}

// Analyze performs comprehensive phishing analysis on a given hostname.
func (a DomainAnalyzer) Analyze(host string) map[string]any {
	popularDomains := a.Popular
	legalDomains := make(map[string]string)

	for brand, domains := range popularDomains {
		for _, d := range domains {
			legalDomains[d] = brand
		}
	}

	replacements := a.LetterReplacements
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

			if a.looksLikeConfusableHomograph(host, legit) {
				count := a.countConfusableCharacters(host)
				if count > 0 {
					patterns = append(patterns, "homograph/confusable character")
					match["homograph_char_count"] = count
				}
			}

			if len(patterns) > 0 {
				match["is_suspicious"] = true
				match["matched_brand"] = brand
				match["matched_legitimate_domain"] = legit
				match["detected_patterns"] = SiteTests.UniqueStrings(patterns)
				match["lookalike_examples"] = []string{fmt.Sprintf("%s resembles %s", host, legit)}
				return match
			}
		}
	}

	return match
}

// EvaluateDomainThreat determines the security threat classification based on the detected
// phishing patterns and analysis metadata.
func EvaluateDomainThreat(metadata map[string]any) SiteTests.ThreatLevel {
	isSuspicious, _ := metadata["is_suspicious"].(bool)
	if !isSuspicious {
		return SiteTests.None
	}

	patterns, _ := metadata["detected_patterns"].([]string)
	homographCount, _ := metadata["homograph_char_count"].(int)

	// Multiple patterns combined with homograph → Critical
	if len(patterns) >= 2 && homographCount > 0 {
		return SiteTests.Critical
	}

	// Multiple patterns without homograph → High
	if len(patterns) >= 2 {
		return SiteTests.High
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
		return SiteTests.High
	}

	// Single pattern (including isolated homograph) → Medium
	return SiteTests.Medium
}

// DescribeDomain creates a human-readable description of the phishing analysis results.
func DescribeDomain(metadata map[string]any) string {
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

// looksLikeConfusableHomograph detects homograph attacks using visually similar Unicode
// characters.
func (a DomainAnalyzer) looksLikeConfusableHomograph(host, legit string) bool {
	normalizedHost := a.normalizeConfusables(host)
	normalizedLegit := a.normalizeConfusables(legit)
	if normalizedHost != normalizedLegit {
		return false
	}

	// Keep this strict to avoid flagging regular ASCII domains.
	return host != legit && containsNonASCII(host)
}

// normalizeConfusables converts confusable Unicode characters to their ASCII equivalents.
func (a DomainAnalyzer) normalizeConfusables(s string) string {
	var out []rune
	for _, r := range strings.ToLower(s) {
		if mapped, ok := a.Confusables[r]; ok {
			out = append(out, mapped)
			continue
		}
		out = append(out, r)
	}
	return string(out)
}

// containsNonASCII checks if a string contains any non-ASCII characters.
func containsNonASCII(s string) bool {
	for _, r := range s {
		if r > utf8.RuneSelf {
			return true
		}
	}
	return false
}

// hasSameSuffix checks if two hostnames share the same domain suffix (TLD and parent domain).
func hasSameSuffix(host, legit string) bool {
	hostParts := strings.Split(host, ".")
	legitParts := strings.Split(legit, ".")
	if len(hostParts) < 2 || len(legitParts) < 2 {
		return false
	}
	return hostParts[len(hostParts)-1] == legitParts[len(legitParts)-1]
}

// isTranspositionVariant detects if a hostname is a variant of a legitimate domain where
// exactly two adjacent characters have been transposed (swapped).
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

// isSingleEditDistance checks if two strings differ by exactly one edit operation (Levenshtein
// distance of 1).
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

// matchesReplacementVariant detects if a hostname matches a legitimate domain with common
// letter replacements applied.
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

// generateReplacementVariants creates all possible letter-replacement variants of a domain
// label.
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

// countConfusableCharacters counts how many confusable Unicode characters are present in a
// string.
func (a DomainAnalyzer) countConfusableCharacters(s string) int {
	count := 0
	for _, r := range s {
		if _, ok := a.Confusables[r]; ok {
			count++
		}
	}
	return count
}

// absInt returns the absolute value of an integer.
func absInt(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
