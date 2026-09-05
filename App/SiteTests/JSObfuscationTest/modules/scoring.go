package modules

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
