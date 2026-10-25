// Package modules holds the stage implementations of the Robots.txt Security Analysis test.
// It is used by its own core.go and nothing else.
package modules

import (
	"Engine-AntiGinx/App/SSRF"
	"Engine-AntiGinx/App/SiteTests"
	"Engine-AntiGinx/App/SiteTests/SensitivePaths"
	"bufio"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

// Robots.txt directives the test reads; every other line is ignored.
const (
	DirectiveAllow    = "Allow"
	DirectiveDisallow = "Disallow"
)

// Fetcher retrieves a target's robots.txt and reports what it reveals.
type Fetcher struct {
	DangerousPatterns SensitivePaths.Matcher
	Timeout           time.Duration
	MaxBodyBytes      int64
}

// RobotsRule is one Allow or Disallow line whose path matched a dangerous pattern.
type RobotsRule struct {
	Directive string `json:"directive"`
	Path      string `json:"path"`
	Pattern   string `json:"pattern"`
	Category  string `json:"category"`
	// Exposed is true for an Allow rule that is not a carve-out of a disallowed sensitive path.
	Exposed bool `json:"exposed"`
}

// RobotsAnalysis represents the analysis results of robots.txt for sensitive path disclosure.
type RobotsAnalysis struct {
	RobotsAccessible bool         `json:"robots_accessible"`
	TotalRules       int          `json:"total_rules"`
	DangerousRules   []RobotsRule `json:"dangerous_rules"`
	TotalDangerous   int          `json:"total_dangerous"`
	TotalExposed     int          `json:"total_exposed"`
}

// rawRule is a parsed Allow or Disallow line before it is matched.
type rawRule struct {
	directive string
	path      string
}

// Analyze fetches and analyzes the robots.txt file for sensitive path disclosure.
func (f Fetcher) Analyze(baseUrl string) RobotsAnalysis {
	robotsUrl := baseUrl + "/robots.txt"

	analysis := RobotsAnalysis{DangerousRules: []RobotsRule{}}

	resp, err := SSRF.NewClient(f.Timeout).Get(robotsUrl)
	if err != nil {
		return analysis
	}

	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			fmt.Printf("HttpClient \nWarning: Failed to close response channel: %s", cerr.Error())
		}
	}()

	// If robots.txt doesn't exist or is inaccessible, return safe result
	if resp.StatusCode != 200 {
		return analysis
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, f.MaxBodyBytes))
	if err != nil {
		return analysis
	}

	analysis.RobotsAccessible = true
	return f.match(parseRobots(string(body)), analysis)
}

// parseRobots extracts the Allow and Disallow rules from robots.txt content, dropping
// comments, empty values and repeats of the same rule.
func parseRobots(content string) []rawRule {
	rules := []rawRule{}
	seen := map[rawRule]struct{}{}

	scanner := bufio.NewScanner(strings.NewReader(content))
	scanner.Buffer(make([]byte, 0, 64*1024), len(content)+1)
	for scanner.Scan() {
		line := scanner.Text()
		if index := strings.Index(line, "#"); index >= 0 {
			line = line[:index]
		}

		key, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}

		var directive string
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "allow":
			directive = DirectiveAllow
		case "disallow":
			directive = DirectiveDisallow
		default:
			continue
		}

		// An empty Disallow means "nothing is disallowed" and names no path
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}

		rule := rawRule{directive: directive, path: value}
		if _, repeated := seen[rule]; repeated {
			continue
		}
		seen[rule] = struct{}{}
		rules = append(rules, rule)
	}

	return rules
}

// match checks every rule against the dangerous patterns and fills in the analysis.
func (f Fetcher) match(rules []rawRule, analysis RobotsAnalysis) RobotsAnalysis {
	analysis.TotalRules = len(rules)

	disallowedSensitive := []string{}
	for _, rule := range rules {
		pattern, category, ok := f.DangerousPatterns.Best(rule.path)
		if !ok {
			continue
		}
		if rule.directive == DirectiveDisallow {
			disallowedSensitive = append(disallowedSensitive, ruleBase(rule.path))
		}
		analysis.DangerousRules = append(analysis.DangerousRules, RobotsRule{
			Directive: rule.directive,
			Path:      rule.path,
			Pattern:   pattern,
			Category:  category,
		})
	}

	// An Allow under a disallowed sensitive path (WordPress's /wp-admin/admin-ajax.php) only
	// narrows that Disallow; any other Allow invites crawlers into a sensitive area.
	for i := range analysis.DangerousRules {
		rule := &analysis.DangerousRules[i]
		if rule.Directive != DirectiveAllow {
			continue
		}
		rule.Exposed = true
		for _, base := range disallowedSensitive {
			if base != "" && strings.HasPrefix(strings.ToLower(rule.Path), base) {
				rule.Exposed = false
				break
			}
		}
		if rule.Exposed {
			analysis.TotalExposed++
		}
	}

	analysis.TotalDangerous = len(analysis.DangerousRules)
	return analysis
}

// ruleBase is the literal prefix of a rule path, up to its first wildcard or end anchor.
func ruleBase(path string) string {
	if index := strings.IndexAny(path, "*$"); index >= 0 {
		path = path[:index]
	}
	return strings.ToLower(path)
}

// EvaluateThreat grades what the file lets an attacker do. robots.txt is public by design,
// so naming sensitive paths in Disallow rules only aids reconnaissance (CWE-200) and is Info;
// an Allow that invites crawlers into a sensitive area gets it indexed, which is Low. Each
// rule is a disclosure on its own, so the number of rules never raises the level.
func EvaluateThreat(analysis RobotsAnalysis) SiteTests.ThreatLevel {
	switch {
	case !analysis.RobotsAccessible || analysis.TotalDangerous == 0:
		return SiteTests.None
	case analysis.TotalExposed > 0:
		return SiteTests.Low
	default:
		return SiteTests.Info
	}
}

// Describe creates a human-readable description of the robots.txt analysis.
func Describe(analysis RobotsAnalysis) string {
	if !analysis.RobotsAccessible {
		return "Robots.txt is not accessible or does not exist - there are no crawler rules that could reveal sensitive paths."
	}

	if analysis.TotalDangerous == 0 {
		return fmt.Sprintf("Robots.txt is secure - none of its %d Allow/Disallow rules names an administrative interface, configuration, backup or other sensitive path.",
			analysis.TotalRules)
	}

	// Group dangerous rules by category
	categoryGroups := make(map[string][]RobotsRule)
	for _, rule := range analysis.DangerousRules {
		categoryGroups[rule.Category] = append(categoryGroups[rule.Category], rule)
	}
	categories := make([]string, 0, len(categoryGroups))
	for category := range categoryGroups {
		categories = append(categories, category)
	}
	sort.Strings(categories)

	description := fmt.Sprintf("Robots.txt names %d sensitive paths (out of %d Allow/Disallow rules). The file is public, so a Disallow rule does not protect a path - it tells anyone reading it where to look.\n",
		analysis.TotalDangerous, analysis.TotalRules)
	if analysis.TotalExposed > 0 {
		description += fmt.Sprintf("%d of them are Allow rules that explicitly invite crawlers into a sensitive area.\n",
			analysis.TotalExposed)
	}
	description += "\n"

	// Add category breakdown
	for _, category := range categories {
		rules := categoryGroups[category]
		description += fmt.Sprintf("• %s: %d found\n", category, len(rules))

		// Show first 3 examples from each category
		exampleCount := min(len(rules), 3)
		for i := 0; i < exampleCount; i++ {
			description += fmt.Sprintf("  - %s: %s\n", rules[i].Directive, rules[i].Path)
		}
		if len(rules) > 3 {
			description += fmt.Sprintf("  ... and %d more\n", len(rules)-3)
		}
	}

	return description
}
