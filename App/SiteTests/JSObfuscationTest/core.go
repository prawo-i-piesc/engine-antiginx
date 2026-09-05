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
			hasJavaScript := strings.Contains(contentType, "javascript") ||
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
			analysis := detector.Analyze(bodyStr)

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

// evaluateObfuscationThreat determines threat level
func evaluateObfuscationThreat(analysis JSObfuscationAnalysis) SiteTests.ThreatLevel {
	// Critical: Extreme obfuscation with malicious indicators
	if analysis.ObfuscationScore >= 80 || len(analysis.MaliciousIndicators) >= 3 {
		return SiteTests.Critical
	}

	// High: Heavy obfuscation or multiple malicious indicators
	if analysis.ObfuscationScore >= 60 || len(analysis.MaliciousIndicators) >= 2 {
		return SiteTests.High
	}

	// Medium: Moderate obfuscation or some malicious indicators
	if analysis.ObfuscationScore >= 40 || len(analysis.MaliciousIndicators) >= 1 {
		return SiteTests.Medium
	}

	// Low: Light obfuscation
	if analysis.ObfuscationScore >= 20 {
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

	_, _ = fmt.Fprintf(&description, "JavaScript obfuscation detected with %s level (score: %d/100). ",
		analysis.ObfuscationLevel, analysis.ObfuscationScore)

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
