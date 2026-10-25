// Package modules holds the stage implementations of the Phishing URL Analysis test.
// It is used by its own core.go and nothing else.
package modules

import (
	"Engine-AntiGinx/App/SiteTests"
	"fmt"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"
)

// DomainAnalyzer decides whether a hostname impersonates a known brand.
type DomainAnalyzer struct {
	Popular            map[string][]string
	LetterReplacements map[string][]string
	Confusables        map[rune]rune
}

// DomainAnalysis is what the hostname comparison found. Fields are in the alphabetical order
// of their JSON names, the order the metadata map this replaced was serialized in, so
// reports keep the same shape.
type DomainAnalysis struct {
	DetectedPatterns        []string `json:"detected_patterns"`         // Kinds of resemblance found, without repeats
	HomographCharCount      int      `json:"homograph_char_count"`      // Confusable characters in the hostname
	Host                    string   `json:"host"`                      // The hostname analysed
	IsKnownLegitimate       bool     `json:"is_known_legitimate"`       // Whether it is one of the brands' own domains
	IsSuspicious            bool     `json:"is_suspicious"`             // Whether it resembles one of them
	LookalikeExamples       []string `json:"lookalike_examples"`        // "host resembles domain" for the match
	MatchedBrand            string   `json:"matched_brand"`             // The brand owned or imitated
	MatchedLegitimateDomain string   `json:"matched_legitimate_domain"` // The domain owned or imitated
}

// Analyze performs comprehensive phishing analysis on a given hostname. Brands are compared
// in alphabetical order and the first resemblance wins, so a hostname close to two brands
// is always reported against the same one.
func (a DomainAnalyzer) Analyze(host string) DomainAnalysis {
	brands := make([]string, 0, len(a.Popular))
	legalDomains := make(map[string]string)
	for brand, domains := range a.Popular {
		brands = append(brands, brand)
		for _, d := range domains {
			legalDomains[d] = brand
		}
	}
	sort.Strings(brands)

	match := DomainAnalysis{
		DetectedPatterns:  []string{},
		Host:              host,
		LookalikeExamples: []string{},
	}

	// Without a hostname there is nothing to compare against, so the analysis
	// reports no findings instead of matching the empty string against the dataset.
	if host == "" {
		return match
	}

	if brand, ok := legalDomains[host]; ok {
		match.IsKnownLegitimate = true
		match.MatchedBrand = brand
		match.MatchedLegitimateDomain = host
		return match
	}

	for _, brand := range brands {
		for _, legit := range a.Popular[brand] {
			patterns := []string{}

			if hasSameSuffix(host, legit) && isSingleEditDistance(host, legit) {
				patterns = append(patterns, "single-character typo")
			}

			if hasSameSuffix(host, legit) && isTranspositionVariant(host, legit) {
				patterns = append(patterns, "adjacent-letter transposition")
			}

			if hasSameSuffix(host, legit) && matchesReplacementVariant(host, legit, a.LetterReplacements) {
				patterns = append(patterns, "popular letter replacement")
			}

			if a.looksLikeConfusableHomograph(host, legit) {
				count := a.countConfusableCharacters(host)
				if count > 0 {
					patterns = append(patterns, "homograph/confusable character")
					match.HomographCharCount = count
				}
			}

			if len(patterns) > 0 {
				match.IsSuspicious = true
				match.MatchedBrand = brand
				match.MatchedLegitimateDomain = legit
				match.DetectedPatterns = SiteTests.UniqueStrings(patterns)
				match.LookalikeExamples = []string{fmt.Sprintf("%s resembles %s", host, legit)}
				return match
			}
		}
	}

	return match
}

// EvaluateDomainThreat determines the security threat classification based on the detected
// phishing patterns and analysis metadata.
func EvaluateDomainThreat(analysis DomainAnalysis) SiteTests.ThreatLevel {
	if !analysis.IsSuspicious {
		return SiteTests.None
	}

	patterns := analysis.DetectedPatterns
	homographCount := analysis.HomographCharCount

	// Multiple patterns combined with homograph → Critical
	if len(patterns) >= 2 && homographCount > 0 {
		return SiteTests.Critical
	}

	// Multiple patterns without homograph → High
	if len(patterns) >= 2 {
		return SiteTests.High
	}

	// Single homograph pattern with significant character usage → High
	if slices.Contains(patterns, "homograph/confusable character") && homographCount >= 3 {
		return SiteTests.High
	}

	// Single pattern (including isolated homograph) → Medium
	return SiteTests.Medium
}

// DescribeDomain creates a human-readable description of the phishing analysis results.
func DescribeDomain(analysis DomainAnalysis) string {
	if analysis.IsKnownLegitimate {
		return "Domain is recognized as a known legitimate domain from the local popularity dataset"
	}

	if !analysis.IsSuspicious {
		return "No phishing-style typo-squatting or homograph indicators detected against the local popular-domain dataset"
	}

	return fmt.Sprintf(
		"Potential phishing domain detected: %s appears to impersonate %s (%s). Detected patterns: %s",
		analysis.Host,
		analysis.MatchedBrand,
		analysis.MatchedLegitimateDomain,
		strings.Join(analysis.DetectedPatterns, ", "),
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
