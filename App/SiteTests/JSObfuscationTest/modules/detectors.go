// Package modules holds the stage implementations of the JavaScript Obfuscation Detection test.
// It is used by its own core.go and nothing else.
package modules

import (
	"Engine-AntiGinx/App/SiteTests"
	"fmt"
	"regexp"
	"strings"
)

// Patterns are the compiled expressions the detectors match against.
type Patterns struct {
	Script             *regexp.Regexp
	DynamicExecution   map[string]*regexp.Regexp
	EvalOfDecoder      *regexp.Regexp
	Atob               *regexp.Regexp
	Unescape           *regexp.Regexp
	CharCode           *regexp.Regexp
	LargeCharCodeArray *regexp.Regexp
	HexEscape          *regexp.Regexp
	UnicodeEscape      *regexp.Regexp
	Base64Literal      *regexp.Regexp
	StringConcat       *regexp.Regexp
	BracketAccess      *regexp.Regexp
	HexArray           *regexp.Regexp
	MultilayerDecode   *regexp.Regexp
	SuspiciousKeywords []string
}

// Detector runs every obfuscation detector over a page.
type Detector struct {
	Patterns Patterns
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

// Analyze performs comprehensive JavaScript obfuscation analysis
func (d Detector) Analyze(content string) JSObfuscationAnalysis {
	analysis := JSObfuscationAnalysis{
		ObfuscationPatterns: []string{},
		SuspiciousPatterns:  []string{},
		MaliciousIndicators: []string{},
		EncodingMethods:     []string{},
		Certainty:           95,
	}

	// Extract script content
	scripts := d.extractScriptContent(content)
	if len(scripts) == 0 {
		analysis.Certainty = 100
		return analysis
	}

	scriptContent := strings.Join(scripts, "\n")

	// Detect various obfuscation patterns
	d.detectDynamicExecution(&analysis, scriptContent)
	d.detectEncodedStrings(&analysis, scriptContent)
	d.detectCharCodeObfuscation(&analysis, scriptContent)
	d.detectEscapeSequences(&analysis, scriptContent)
	d.detectBase64Encoding(&analysis, scriptContent)
	d.detectSuspiciousPatterns(&analysis, scriptContent)
	d.detectMaliciousIndicators(&analysis, scriptContent)

	// Calculate obfuscation score
	calculateObfuscationScore(&analysis)

	// Determine obfuscation level
	determineObfuscationLevel(&analysis)

	// Check if obfuscation detected
	analysis.HasObfuscation = analysis.ObfuscationScore > 20

	return analysis
}

// extractScriptContent extracts JavaScript from script tags
func (d Detector) extractScriptContent(html string) []string {
	scripts := []string{}

	// Match script tags
	scriptRegex := d.Patterns.Script
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
func (d Detector) detectDynamicExecution(analysis *JSObfuscationAnalysis, content string) {
	patterns := d.Patterns.DynamicExecution

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
	evalObfuscated := d.Patterns.EvalOfDecoder
	if evalObfuscated.MatchString(content) {
		analysis.MaliciousIndicators = append(analysis.MaliciousIndicators,
			"eval() called with encoded/decoded input - high risk pattern")
		analysis.DynamicExecution += 10 // Heavy weight for this pattern
	}
}

// detectEncodedStrings detects various string encoding methods
func (d Detector) detectEncodedStrings(analysis *JSObfuscationAnalysis, content string) {
	// Detect atob (Base64 decode)
	atobRegex := d.Patterns.Atob
	if matches := atobRegex.FindAllString(content, -1); len(matches) > 0 {
		analysis.EncodedStrings += len(matches)
		analysis.EncodingMethods = append(analysis.EncodingMethods, "Base64 (atob)")
		analysis.ObfuscationPatterns = append(analysis.ObfuscationPatterns,
			fmt.Sprintf("Base64 decoding found %d times", len(matches)))
	}

	// Detect unescape/decodeURI
	unescapeRegex := d.Patterns.Unescape
	if matches := unescapeRegex.FindAllString(content, -1); len(matches) > 0 {
		analysis.EncodedStrings += len(matches)
		analysis.EncodingMethods = append(analysis.EncodingMethods, "URL encoding")
		analysis.ObfuscationPatterns = append(analysis.ObfuscationPatterns,
			fmt.Sprintf("URL decoding found %d times", len(matches)))
	}
}

// detectCharCodeObfuscation detects String.fromCharCode obfuscation
func (d Detector) detectCharCodeObfuscation(analysis *JSObfuscationAnalysis, content string) {
	charCodeRegex := d.Patterns.CharCode
	matches := charCodeRegex.FindAllString(content, -1)

	if len(matches) > 0 {
		analysis.CharCodeUsage = len(matches)
		analysis.EncodingMethods = append(analysis.EncodingMethods, "Character code conversion")
		analysis.ObfuscationPatterns = append(analysis.ObfuscationPatterns,
			fmt.Sprintf("String.fromCharCode used %d times", len(matches)))

		// Detect large character code arrays (strong obfuscation indicator)
		largeArrayRegex := d.Patterns.LargeCharCodeArray
		if largeArrayRegex.MatchString(content) {
			analysis.SuspiciousPatterns = append(analysis.SuspiciousPatterns,
				"Large character code arrays detected - heavy obfuscation")
		}
	}
}

// detectEscapeSequences detects hex and unicode escape sequences
func (d Detector) detectEscapeSequences(analysis *JSObfuscationAnalysis, content string) {
	// Hex escape sequences (\x41\x42...)
	hexEscapeRegex := d.Patterns.HexEscape
	hexMatches := hexEscapeRegex.FindAllString(content, -1)
	if len(hexMatches) > 10 { // Threshold to avoid false positives
		analysis.HexEscapes = len(hexMatches)
		analysis.EncodingMethods = append(analysis.EncodingMethods, "Hex escape sequences")
		analysis.ObfuscationPatterns = append(analysis.ObfuscationPatterns,
			fmt.Sprintf("Hex escape sequences: %d occurrences", len(hexMatches)))
	}

	// Unicode escape sequences (\u0041\u0042...)
	unicodeEscapeRegex := d.Patterns.UnicodeEscape
	unicodeMatches := unicodeEscapeRegex.FindAllString(content, -1)
	if len(unicodeMatches) > 10 { // Threshold to avoid false positives
		analysis.UnicodeEscapes = len(unicodeMatches)
		analysis.EncodingMethods = append(analysis.EncodingMethods, "Unicode escape sequences")
		analysis.ObfuscationPatterns = append(analysis.ObfuscationPatterns,
			fmt.Sprintf("Unicode escape sequences: %d occurrences", len(unicodeMatches)))
	}
}

// detectBase64Encoding detects Base64 encoded strings
func (d Detector) detectBase64Encoding(analysis *JSObfuscationAnalysis, content string) {
	// Look for long Base64-like strings
	base64Regex := d.Patterns.Base64Literal
	matches := base64Regex.FindAllString(content, -1)

	if len(matches) > 0 {
		analysis.Base64Strings = len(matches)
		analysis.EncodingMethods = append(analysis.EncodingMethods, "Base64 encoded strings")
		analysis.ObfuscationPatterns = append(analysis.ObfuscationPatterns,
			fmt.Sprintf("Base64 encoded strings: %d found", len(matches)))
	}
}

// detectSuspiciousPatterns detects patterns commonly associated with obfuscation
func (d Detector) detectSuspiciousPatterns(analysis *JSObfuscationAnalysis, content string) {
	// Self-modifying code
	if matched, _ := regexp.MatchString(`document\.write\s*\(\s*(?:unescape|atob|String\.fromCharCode)`, content); matched {
		analysis.SuspiciousPatterns = append(analysis.SuspiciousPatterns,
			"Self-modifying code: document.write with decoded content")
	}

	// Excessive string concatenation
	concatRegex := d.Patterns.StringConcat
	if matches := concatRegex.FindAllString(content, -1); len(matches) > 20 {
		analysis.SuspiciousPatterns = append(analysis.SuspiciousPatterns,
			fmt.Sprintf("Excessive string concatenation: %d instances", len(matches)))
	}

	// Bracket notation obfuscation (e.g., window["eval"])
	bracketRegex := d.Patterns.BracketAccess
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
	if d.Patterns.HexArray.MatchString(content) {
		analysis.SuspiciousPatterns = append(analysis.SuspiciousPatterns,
			"Hexadecimal number arrays detected")
	}
}

// detectMaliciousIndicators detects patterns strongly associated with malicious code
func (d Detector) detectMaliciousIndicators(analysis *JSObfuscationAnalysis, content string) {
	contentLower := strings.ToLower(content)

	// Multiple layers of encoding
	multilayerRegex := d.Patterns.MultilayerDecode
	if multilayerRegex.MatchString(content) {
		analysis.MaliciousIndicators = append(analysis.MaliciousIndicators,
			"Multiple layers of encoding detected - strong obfuscation")
	}

	// eval chains
	if matched, _ := regexp.MatchString(`eval\s*\([^)]*eval\s*\(`, content); matched {
		analysis.MaliciousIndicators = append(analysis.MaliciousIndicators,
			"Nested eval() calls - possible code injection")
	}

	// Suspicious keywords, but only where the page is also hiding something. The keyword
	// alone means nothing; in obfuscated code it speaks to intent. Reported once.
	if analysis.EncodedStrings > 0 || analysis.DynamicExecution > 0 {
		if found := SiteTests.FindAllFold(contentLower, d.Patterns.SuspiciousKeywords); len(found) > 0 {
			analysis.MaliciousIndicators = append(analysis.MaliciousIndicators,
				fmt.Sprintf("Suspicious keyword '%s' found in obfuscated context", found[0]))
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
