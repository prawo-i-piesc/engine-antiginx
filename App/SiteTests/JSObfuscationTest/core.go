// Package JSObfuscationTest implements the JavaScript Obfuscation Detection security test.
// See README.md for what it checks, how it grades and what it reports.
package JSObfuscationTest

import (
	"Engine-AntiGinx/App/SiteTests"
	"Engine-AntiGinx/App/SiteTests/JSObfuscationTest/modules"
	"fmt"
	"io"
	"strings"
)

// JSObfuscationAnalysis is the detailed outcome of the scan.
type JSObfuscationAnalysis = modules.JSObfuscationAnalysis

// detector wires the pattern set owned by this package into the detection stage.
var detector = modules.Detector{Patterns: obfuscationPatterns}

// New creates a new ResponseTest that analyzes JavaScript code for obfuscation.
func New() *SiteTests.ResponseTest {
	return &SiteTests.ResponseTest{
		Id:          TestId,
		Name:        TestName,
		Description: TestDescription,
		Category:    TestCategory,
		RunTest: func(params SiteTests.ResponseTestParams) SiteTests.TestResult {
			// Read response body
			bodyBytes, err := io.ReadAll(params.Response.Body)
			if err != nil {
				return SiteTests.TestResult{
					Name:        TestName,
					Certainty:   50,
					ThreatLevel: SiteTests.Info,
					Metadata:    nil,
					Description: "Unable to read response body for JavaScript analysis.",
				}
			}
			bodyStr := string(bodyBytes)

			// Check if response contains JavaScript
			contentType := params.Response.Header.Get("Content-Type")
			isScript := strings.Contains(strings.ToLower(contentType), "javascript") ||
				strings.Contains(strings.ToLower(contentType), "ecmascript")
			hasJavaScript := isScript ||
				strings.Contains(bodyStr, "<script") ||
				strings.Contains(contentType, "html")

			if !hasJavaScript {
				return SiteTests.TestResult{
					Name:        TestName,
					Certainty:   100,
					ThreatLevel: SiteTests.None,
					Metadata:    nil,
					Description: "No JavaScript content detected in response.",
				}
			}

			// Analyze JavaScript for obfuscation
			// A JavaScript file is one script as a whole; a page carries its scripts in
			// <script> elements.
			var analysis JSObfuscationAnalysis
			if isScript {
				analysis = detector.AnalyzeScript(bodyStr)
			} else {
				analysis = detector.Analyze(bodyStr)
			}

			// Determine threat level
			threatLevel := evaluateObfuscationThreat(analysis)

			// Generate description
			description := generateObfuscationDescription(analysis)

			return SiteTests.TestResult{
				Name:        TestName,
				Certainty:   analysis.Certainty,
				ThreatLevel: threatLevel,
				Metadata:    analysis,
				Description: description,
			}
		},
	}
}

// evaluateObfuscationThreat grades the evidence that the page itself is malicious. Obfuscation
// alone is not a vulnerability and never rises above Low; only malicious indicators, which
// show what the hidden code does, reach Medium (one) or High (two or more independent ones).
// Nothing is Critical, which is reserved for CVEs rated Critical.
func evaluateObfuscationThreat(analysis JSObfuscationAnalysis) SiteTests.ThreatLevel {
	if len(analysis.MaliciousIndicators) >= 2 {
		return SiteTests.High
	}
	if len(analysis.MaliciousIndicators) == 1 {
		return SiteTests.Medium
	}

	// Low: Obfuscated, the point from which the page counts as obfuscated, at any score
	if analysis.ObfuscationScore >= modules.ObfuscationThreshold {
		return SiteTests.Low
	}

	// Info: Very minimal patterns (likely just minification)
	if analysis.ObfuscationScore >= 10 {
		return SiteTests.Info
	}

	// None: No obfuscation detected
	return SiteTests.None
}

// generateObfuscationDescription creates detailed description
func generateObfuscationDescription(analysis JSObfuscationAnalysis) string {
	if !analysis.HasObfuscation {
		return "No JavaScript obfuscation detected - code appears clean and readable."
	}

	var description strings.Builder

	_, _ = fmt.Fprintf(&description, "JavaScript obfuscation detected: %s obfuscation (score: %d/100). ",
		analysis.ObfuscationLevel, analysis.ObfuscationScore)

	// Malicious indicators first: they, not the amount of obfuscation, decide the grade
	if len(analysis.MaliciousIndicators) > 0 {
		description.WriteString("MALICIOUS INDICATORS: ")
		description.WriteString(strings.Join(analysis.MaliciousIndicators, "; "))
		description.WriteString(". ")
	} else {
		description.WriteString("No malicious indicators: obfuscation alone does not show what the code does. ")
	}

	// Encoding methods
	if len(analysis.EncodingMethods) > 0 {
		description.WriteString("Encoding methods detected: ")
		description.WriteString(strings.Join(analysis.EncodingMethods, ", "))
		description.WriteString(". ")
	}

	// Key statistics
	if analysis.DynamicExecution > 0 || analysis.EncodedStrings > 0 {
		_, _ = fmt.Fprintf(&description, "Found: %d dynamic execution calls, %d encoded strings. ",
			analysis.DynamicExecution, analysis.EncodedStrings)
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
			_, _ = fmt.Fprintf(&description, " and %d more", len(analysis.SuspiciousPatterns)-maxPatterns)
		}
		description.WriteString(".")
	}

	return description.String()
}
