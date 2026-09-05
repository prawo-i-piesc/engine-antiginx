package modules

// calculateCookieSecurityScore calculates overall security score (0-100)
func calculateCookieSecurityScore(analysis *CookieSecurityAnalysis) {
	if analysis.TotalCookies == 0 {
		analysis.OverallSecurityScore = 100
		return
	}

	totalScore := 0
	for _, detail := range analysis.CookieDetails {
		totalScore += detail.SecurityScore
	}

	analysis.OverallSecurityScore = totalScore / analysis.TotalCookies

	// Apply penalties for critical issues
	if analysis.InsecureSession {
		analysis.OverallSecurityScore -= 30
	}
	if analysis.FixationRisk {
		analysis.OverallSecurityScore -= 20
	}

	// Ensure score is within bounds
	if analysis.OverallSecurityScore < 0 {
		analysis.OverallSecurityScore = 0
	}
	if analysis.OverallSecurityScore > 100 {
		analysis.OverallSecurityScore = 100
	}
}

// calculateIndividualCookieScore calculates security score for a single cookie
func calculateIndividualCookieScore(detail CookieSecurityDetail) int {
	score := 100

	// Deduct for missing security flags
	if !detail.HasHttpOnly {
		score -= 25
	}

	//Before lint
	//if !detail.HasSecure {
	//	score -= 25
	//}
	//if detail.SameSite == "" || detail.SameSite == "None" {
	//	score -= 20
	//} else if detail.SameSite == "Lax" {
	//	score -= 5 // Minor deduction, Strict is better
	//}

	// After lint
	switch detail.SameSite {
	case "":
		score -= 20
	case "None":
		score -= 20
	case "Lax":
		score -= 5
	}

	// Deduct for long expiration
	if detail.MaxAge > 31536000 {
		score -= 15
	} else if detail.MaxAge > 7776000 {
		score -= 5
	}

	// Deduct for predictable values
	if detail.PredictableValue {
		score -= 15
	}

	// Extra penalty for insecure session cookies
	if detail.IsSessionCookie && (!detail.HasHttpOnly || !detail.HasSecure) {
		score -= 10
	}

	if score < 0 {
		score = 0
	}

	return score
}
