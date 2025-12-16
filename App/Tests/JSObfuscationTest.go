// Package Tests provides security test implementations for HTTP response analysis.
// This file contains the JavaScript Obfuscation test that detects obfuscated JavaScript code
// which may indicate malicious activity, code hiding, or security evasion techniques.
package Tests

import (
	"fmt"
	"io"
	"regexp"
	"strings"
)

// NewJSObfuscationTest creates a new ResponseTest that analyzes JavaScript code for obfuscation.
// Obfuscated JavaScript is often used by attackers to hide malicious payloads, evade detection,
// or make reverse engineering difficult. While legitimate sites may use minification, heavy
// obfuscation is a red flag for potential security threats.
//
// The test evaluates:
//   - Encoded strings (Base64, hex, unicode escape sequences)
//   - Character substitution patterns
//   - Excessive use of eval(), Function(), or similar dynamic execution
//   - String concatenation obfuscation
//   - Highly compressed or minimized code patterns
//   - Suspicious variable/function naming patterns
//   - Code that decodes or decrypts itself at runtime
//
// Threat level assessment:
//   - None (0): No obfuscation detected, clean JavaScript code
//   - Info (1): Minor minification or basic optimization detected
//   - Low (2): Some obfuscation patterns but likely legitimate (e.g., webpack bundles)
//   - Medium (3): Moderate obfuscation with multiple suspicious patterns
//   - High (4): Heavy obfuscation with clear intent to hide functionality
//   - Critical (5): Extremely obfuscated code with malicious indicators
//
// Security implications:
//   - Obfuscated code can hide malicious payloads (keyloggers, data exfiltration)
//   - May indicate compromised website or injected malware
//   - Can evade security scanners and code review
//   - Often used in drive-by download attacks
//   - May hide cryptocurrency miners or ad fraud scripts
//
// Detection patterns:
//   - Base64 encoded strings followed by decode/atob
//   - Hex escape sequences (\x41\x42\x43)
//   - Unicode escape sequences (\u0041\u0042\u0043)
//   - eval() with encoded or constructed strings
//   - String.fromCharCode() with numeric arrays
//   - Excessive string concatenation
//   - Self-modifying or self-decrypting code
//
// Returns:
//   - *ResponseTest: Configured JavaScript obfuscation test ready for execution
//
// Example usage:
//
//	jsObfTest := NewJSObfuscationTest()
//	result := jsObfTest.Run(ResponseTestParams{Response: httpResponse})
//	// Result includes threat level and detailed obfuscation analysis
func NewJSObfuscationTest() *ResponseTest {
	return &ResponseTest{
		Id:          "js-obf",
		Name:        "JavaScript Obfuscation Detection",
		Description: "Detects obfuscated JavaScript code that may indicate malicious activity or security evasion techniques",
		RunTest: func(params ResponseTestParams) TestResult {
			// Read response body
			bodyBytes, err := io.ReadAll(params.Response.Body)
			if err != nil {
				return TestResult{
					Name:        "JavaScript Obfuscation Detection",
					Certainty:   50,
					ThreatLevel: Info,
					Metadata:    nil,
					Description: "Unable to read response body for JavaScript analysis.",
				}
			}
			bodyStr := string(bodyBytes)

			// Check if response contains JavaScript
			contentType := params.Response.Header.Get("Content-Type")
			hasJavaScript := strings.Contains(contentType, "javascript") ||
				strings.Contains(bodyStr, "<script") ||
				strings.Contains(contentType, "html")

			if !hasJavaScript {
				return TestResult{
					Name:        "JavaScript Obfuscation Detection",
					Certainty:   100,
					ThreatLevel: None,
					Metadata:    nil,
					Description: "No JavaScript content detected in response.",
				}
			}

			// Analyze JavaScript for obfuscation
			analysis := analyzeJSObfuscation(bodyStr)

			// Determine threat level
			threatLevel := evaluateObfuscationThreat(analysis)

			// Generate description
			description := generateObfuscationDescription(analysis)

			return TestResult{
				Name:        "JavaScript Obfuscation Detection",
				Certainty:   analysis.Certainty,
				ThreatLevel: threatLevel,
				Metadata:    analysis,
				Description: description,
			}
		},
	}
}

// JSObfuscationAnalysis represents the comprehensive obfuscation analysis
type JSObfuscationAnalysis struct {
	HasObfuscation      bool     `json:"hasObfuscation"`
	ObfuscationScore    int      `json:"obfuscationScore"` // 0-100
	ObfuscationPatterns []string `json:"obfuscationPatterns"`
	SuspiciousPatterns  []string `json:"suspiciousPatterns"`
	MaliciousIndicators []string `json:"maliciousIndicators"`
	EncodingMethods     []string `json:"encodingMethods"`
	DynamicExecution    int      `json:"dynamicExecution"` // Count of eval/Function calls
	EncodedStrings      int      `json:"encodedStrings"`   // Count of encoded strings
	CharCodeUsage       int      `json:"charCodeUsage"`    // String.fromCharCode usage
	HexEscapes          int      `json:"hexEscapes"`       // \x escape sequences
	UnicodeEscapes      int      `json:"unicodeEscapes"`   // \u escape sequences
	Base64Strings       int      `json:"base64Strings"`    // Base64 encoded strings
	ObfuscationLevel    string   `json:"obfuscationLevel"` // none, light, moderate, heavy, extreme
	Certainty           int      `json:"certainty"`        // 0-100
}

// analyzeJSObfuscation performs comprehensive JavaScript obfuscation analysis
func analyzeJSObfuscation(content string) JSObfuscationAnalysis {
	analysis := JSObfuscationAnalysis{
		ObfuscationPatterns: []string{},
		SuspiciousPatterns:  []string{},
		MaliciousIndicators: []string{},
		EncodingMethods:     []string{},
		Certainty:           95,
	}

	// Extract script content
	scripts := extractScriptContent(content)
	if len(scripts) == 0 {
		analysis.Certainty = 100
		return analysis
	}

	scriptContent := strings.Join(scripts, "\n")

	// Detect various obfuscation patterns
	detectDynamicExecution(&analysis, scriptContent)
	detectEncodedStrings(&analysis, scriptContent)
	detectCharCodeObfuscation(&analysis, scriptContent)
	detectEscapeSequences(&analysis, scriptContent)
	detectBase64Encoding(&analysis, scriptContent)
	detectSuspiciousPatterns(&analysis, scriptContent)
	detectMaliciousIndicators(&analysis, scriptContent)

	// Calculate obfuscation score
	calculateObfuscationScore(&analysis)

	// Determine obfuscation level
	determineObfuscationLevel(&analysis)

	// Check if obfuscation detected
	analysis.HasObfuscation = analysis.ObfuscationScore > 20

	return analysis
}

// extractScriptContent extracts JavaScript from script tags
func extractScriptContent(html string) []string {
	scripts := []string{}

	// Match script tags
	scriptRegex := regexp.MustCompile(`(?is)<script[^>]*>(.*?)</script>`)
	matches := scriptRegex.FindAllStringSubmatch(html, -1)

	for _, match := range matches {
		if len(match) > 1 && strings.TrimSpace(match[1]) != "" {
			// Skip external scripts (src attribute only)
			if !strings.Contains(match[0], "src=") || len(match[1]) > 10 {
				scripts = append(scripts, match[1])
			}
		}
	}

	return scripts
}

// detectDynamicExecution detects eval, Function, and similar dynamic code execution
func detectDynamicExecution(analysis *JSObfuscationAnalysis, content string) {
	patterns := map[string]*regexp.Regexp{
		"eval":        regexp.MustCompile(`\beval\s*\(`),
		"Function":    regexp.MustCompile(`\bFunction\s*\(`),
		"setTimeout":  regexp.MustCompile(`setTimeout\s*\(\s*["']`),
		"setInterval": regexp.MustCompile(`setInterval\s*\(\s*["']`),
	}

	for patternName, regex := range patterns {
		matches := regex.FindAllString(content, -1)
		count := len(matches)
		if count > 0 {
			analysis.DynamicExecution += count
			analysis.ObfuscationPatterns = append(analysis.ObfuscationPatterns,
				fmt.Sprintf("Dynamic execution: %s used %d times", patternName, count))
		}
	}

	// Detect eval with encoded/obfuscated input
	evalObfuscated := regexp.MustCompile(`eval\s*\(\s*(?:atob|unescape|decodeURI|String\.fromCharCode)`)
	if evalObfuscated.MatchString(content) {
		analysis.MaliciousIndicators = append(analysis.MaliciousIndicators,
			"eval() called with encoded/decoded input - high risk pattern")
		analysis.DynamicExecution += 10 // Heavy weight for this pattern
	}
}

// detectEncodedStrings detects various string encoding methods
func detectEncodedStrings(analysis *JSObfuscationAnalysis, content string) {
	// Detect atob (Base64 decode)
	atobRegex := regexp.MustCompile(`atob\s*\(`)
	if matches := atobRegex.FindAllString(content, -1); len(matches) > 0 {
		analysis.EncodedStrings += len(matches)
		analysis.EncodingMethods = append(analysis.EncodingMethods, "Base64 (atob)")
		analysis.ObfuscationPatterns = append(analysis.ObfuscationPatterns,
			fmt.Sprintf("Base64 decoding found %d times", len(matches)))
	}

	// Detect unescape/decodeURI
	unescapeRegex := regexp.MustCompile(`\b(?:unescape|decodeURI|decodeURIComponent)\s*\(`)
	if matches := unescapeRegex.FindAllString(content, -1); len(matches) > 0 {
		analysis.EncodedStrings += len(matches)
		analysis.EncodingMethods = append(analysis.EncodingMethods, "URL encoding")
		analysis.ObfuscationPatterns = append(analysis.ObfuscationPatterns,
			fmt.Sprintf("URL decoding found %d times", len(matches)))
	}
}

// detectCharCodeObfuscation detects String.fromCharCode obfuscation
func detectCharCodeObfuscation(analysis *JSObfuscationAnalysis, content string) {
	charCodeRegex := regexp.MustCompile(`String\.fromCharCode\s*\(`)
	matches := charCodeRegex.FindAllString(content, -1)

	if len(matches) > 0 {
		analysis.CharCodeUsage = len(matches)
		analysis.EncodingMethods = append(analysis.EncodingMethods, "Character code conversion")
		analysis.ObfuscationPatterns = append(analysis.ObfuscationPatterns,
			fmt.Sprintf("String.fromCharCode used %d times", len(matches)))

		// Detect large character code arrays (strong obfuscation indicator)
		largeArrayRegex := regexp.MustCompile(`String\.fromCharCode\s*\([^)]{100,}\)`)
		if largeArrayRegex.MatchString(content) {
			analysis.SuspiciousPatterns = append(analysis.SuspiciousPatterns,
				"Large character code arrays detected - heavy obfuscation")
		}
	}
}

// detectEscapeSequences detects hex and unicode escape sequences
func detectEscapeSequences(analysis *JSObfuscationAnalysis, content string) {
	// Hex escape sequences (\x41\x42...)
	hexEscapeRegex := regexp.MustCompile(`\\x[0-9a-fA-F]{2}`)
	hexMatches := hexEscapeRegex.FindAllString(content, -1)
	if len(hexMatches) > 10 { // Threshold to avoid false positives
		analysis.HexEscapes = len(hexMatches)
		analysis.EncodingMethods = append(analysis.EncodingMethods, "Hex escape sequences")
		analysis.ObfuscationPatterns = append(analysis.ObfuscationPatterns,
			fmt.Sprintf("Hex escape sequences: %d occurrences", len(hexMatches)))
	}

	// Unicode escape sequences (\u0041\u0042...)
	unicodeEscapeRegex := regexp.MustCompile(`\\u[0-9a-fA-F]{4}`)
	unicodeMatches := unicodeEscapeRegex.FindAllString(content, -1)
	if len(unicodeMatches) > 10 { // Threshold to avoid false positives
		analysis.UnicodeEscapes = len(unicodeMatches)
		analysis.EncodingMethods = append(analysis.EncodingMethods, "Unicode escape sequences")
		analysis.ObfuscationPatterns = append(analysis.ObfuscationPatterns,
			fmt.Sprintf("Unicode escape sequences: %d occurrences", len(unicodeMatches)))
	}
}

// detectBase64Encoding detects Base64 encoded strings
func detectBase64Encoding(analysis *JSObfuscationAnalysis, content string) {
	// Look for long Base64-like strings
	base64Regex := regexp.MustCompile(`["'][A-Za-z0-9+/]{40,}={0,2}["']`)
	matches := base64Regex.FindAllString(content, -1)

	if len(matches) > 0 {
		analysis.Base64Strings = len(matches)
		analysis.EncodingMethods = append(analysis.EncodingMethods, "Base64 encoded strings")
		analysis.ObfuscationPatterns = append(analysis.ObfuscationPatterns,
			fmt.Sprintf("Base64 encoded strings: %d found", len(matches)))
	}
}

// detectSuspiciousPatterns detects patterns commonly associated with obfuscation
func detectSuspiciousPatterns(analysis *JSObfuscationAnalysis, content string) {
	// Self-modifying code
	if matched, _ := regexp.MatchString(`document\.write\s*\(\s*(?:unescape|atob|String\.fromCharCode)`, content); matched {
		analysis.SuspiciousPatterns = append(analysis.SuspiciousPatterns,
			"Self-modifying code: document.write with decoded content")
	}

	// Excessive string concatenation
	concatRegex := regexp.MustCompile(`['"]\s*\+\s*['"]`)
	if matches := concatRegex.FindAllString(content, -1); len(matches) > 20 {
		analysis.SuspiciousPatterns = append(analysis.SuspiciousPatterns,
			fmt.Sprintf("Excessive string concatenation: %d instances", len(matches)))
	}

	// Bracket notation obfuscation (e.g., window["eval"])
	bracketRegex := regexp.MustCompile(`\w+\["(?:eval|Function|setTimeout|setInterval)"\]`)
	if bracketRegex.MatchString(content) {
		analysis.SuspiciousPatterns = append(analysis.SuspiciousPatterns,
			"Bracket notation used to access dangerous functions")
	}

	// Extremely long lines (common in minified/obfuscated code)
	lines := strings.Split(content, "\n")
	longLines := 0
	for _, line := range lines {
		if len(line) > 500 {
			longLines++
		}
	}
	if longLines > 5 {
		analysis.SuspiciousPatterns = append(analysis.SuspiciousPatterns,
			fmt.Sprintf("Extremely long code lines: %d lines over 500 characters", longLines))
	}

	// Hexadecimal or octal number arrays
	if regexp.MustCompile(`\[(?:\s*0x[0-9a-fA-F]+\s*,?){10,}\]`).MatchString(content) {
		analysis.SuspiciousPatterns = append(analysis.SuspiciousPatterns,
			"Hexadecimal number arrays detected")
	}
}

// detectMaliciousIndicators detects patterns strongly associated with malicious code
func detectMaliciousIndicators(analysis *JSObfuscationAnalysis, content string) {
	contentLower := strings.ToLower(content)

	// Multiple layers of encoding
	multilayerRegex := regexp.MustCompile(`(?:atob|unescape|decodeURI)\s*\(\s*(?:atob|unescape|decodeURI)`)
	if multilayerRegex.MatchString(content) {
		analysis.MaliciousIndicators = append(analysis.MaliciousIndicators,
			"Multiple layers of encoding detected - strong obfuscation")
	}

	// eval chains
	if matched, _ := regexp.MatchString(`eval\s*\([^)]*eval\s*\(`, content); matched {
		analysis.MaliciousIndicators = append(analysis.MaliciousIndicators,
			"Nested eval() calls - possible code injection")
	}

	// Suspicious keywords in obfuscated context
	suspiciousKeywords := []string{"shell", "cmd", "exec", "payload", "exploit", "backdoor"}
	for _, keyword := range suspiciousKeywords {
		if strings.Contains(contentLower, keyword) && (analysis.EncodedStrings > 0 || analysis.DynamicExecution > 0) {
			analysis.MaliciousIndicators = append(analysis.MaliciousIndicators,
				fmt.Sprintf("Suspicious keyword '%s' found in obfuscated context", keyword))
			break // Only report once
		}
	}

	// Code that appears to decrypt itself
	if matched, _ := regexp.MatchString(`for\s*\([^)]+\)\s*{[^}]*(?:\^|<<|>>|&|\|)`, content); matched {
		if analysis.EncodedStrings > 0 {
			analysis.MaliciousIndicators = append(analysis.MaliciousIndicators,
				"Possible self-decrypting code detected")
		}
	}
}

// calculateObfuscationScore calculates overall obfuscation score (0-100)
func calculateObfuscationScore(analysis *JSObfuscationAnalysis) {
	score := 0

	// Dynamic execution (eval, Function, etc.)
	score += analysis.DynamicExecution * 5
	if analysis.DynamicExecution > 10 {
		score += 20 // Extra penalty for excessive use
	}

	// Encoded strings
	score += analysis.EncodedStrings * 8

	// Character code usage
	score += analysis.CharCodeUsage * 6

	// Escape sequences
	if analysis.HexEscapes > 10 {
		score += 15
	}
	if analysis.UnicodeEscapes > 10 {
		score += 15
	}

	// Base64 strings
	score += analysis.Base64Strings * 5

	// Suspicious patterns
	score += len(analysis.SuspiciousPatterns) * 10

	// Malicious indicators (heavy weight)
	score += len(analysis.MaliciousIndicators) * 25

	// Cap at 100
	if score > 100 {
		score = 100
	}

	analysis.ObfuscationScore = score
}

// determineObfuscationLevel categorizes obfuscation severity
func determineObfuscationLevel(analysis *JSObfuscationAnalysis) {
	score := analysis.ObfuscationScore

	if score >= 80 {
		analysis.ObfuscationLevel = "extreme"
	} else if score >= 60 {
		analysis.ObfuscationLevel = "heavy"
	} else if score >= 40 {
		analysis.ObfuscationLevel = "moderate"
	} else if score >= 20 {
		analysis.ObfuscationLevel = "light"
	} else {
		analysis.ObfuscationLevel = "none"
	}
}

// evaluateObfuscationThreat determines threat level
func evaluateObfuscationThreat(analysis JSObfuscationAnalysis) ThreatLevel {
	// Critical: Extreme obfuscation with malicious indicators
	if analysis.ObfuscationScore >= 80 || len(analysis.MaliciousIndicators) >= 3 {
		return Critical
	}

	// High: Heavy obfuscation or multiple malicious indicators
	if analysis.ObfuscationScore >= 60 || len(analysis.MaliciousIndicators) >= 2 {
		return High
	}

	// Medium: Moderate obfuscation or some malicious indicators
	if analysis.ObfuscationScore >= 40 || len(analysis.MaliciousIndicators) >= 1 {
		return Medium
	}

	// Low: Light obfuscation
	if analysis.ObfuscationScore >= 20 {
		return Low
	}

	// Info: Very minimal patterns (likely just minification)
	if analysis.ObfuscationScore >= 10 {
		return Info
	}

	// None: No obfuscation detected
	return None
}

// generateObfuscationDescription creates detailed description
func generateObfuscationDescription(analysis JSObfuscationAnalysis) string {
	if !analysis.HasObfuscation {
		return "No JavaScript obfuscation detected - code appears clean and readable."
	}

	var description strings.Builder

	description.WriteString(fmt.Sprintf("JavaScript obfuscation detected with %s level (score: %d/100). ",
		analysis.ObfuscationLevel, analysis.ObfuscationScore))

	// Malicious indicators first
	if len(analysis.MaliciousIndicators) > 0 {
		description.WriteString("MALICIOUS INDICATORS: ")
		description.WriteString(strings.Join(analysis.MaliciousIndicators, "; "))
		description.WriteString(". ")
	}

	// Encoding methods
	if len(analysis.EncodingMethods) > 0 {
		description.WriteString("Encoding methods detected: ")
		description.WriteString(strings.Join(analysis.EncodingMethods, ", "))
		description.WriteString(". ")
	}

	// Key statistics
	if analysis.DynamicExecution > 0 || analysis.EncodedStrings > 0 {
		description.WriteString(fmt.Sprintf("Found: %d dynamic execution calls, %d encoded strings. ",
			analysis.DynamicExecution, analysis.EncodedStrings))
	}

	// Suspicious patterns
	if len(analysis.SuspiciousPatterns) > 0 {
		description.WriteString("Suspicious patterns: ")
		maxPatterns := 2
		if len(analysis.SuspiciousPatterns) < maxPatterns {
			maxPatterns = len(analysis.SuspiciousPatterns)
		}
		description.WriteString(strings.Join(analysis.SuspiciousPatterns[:maxPatterns], "; "))
		if len(analysis.SuspiciousPatterns) > maxPatterns {
			description.WriteString(fmt.Sprintf(" and %d more", len(analysis.SuspiciousPatterns)-maxPatterns))
		}
		description.WriteString(".")
	}

	return description.String()
}
