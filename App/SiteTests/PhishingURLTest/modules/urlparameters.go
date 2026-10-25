package modules

import (
	"Engine-AntiGinx/App/SiteTests"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
)

// ParameterAnalyzer decides what the non-hostname part of a URL is carrying.
type ParameterAnalyzer struct {
	Credential            []string
	Sensitive             []string
	Identity              []string
	Redirect              []string
	DangerousSchemes      []string
	PathKeywords          []string
	Brands                []string
	MaxQueryLength        int
	MaxParameterCount     int
	MinBrandKeywordLength int
	RedactedPlaceholder   string
}

// ParameterAnalysis is what the path, query and userinfo of a URL carry. Fields are in the
// alphabetical order of their JSON names, the order the metadata map this replaced was
// serialized in, so reports keep the same shape.
type ParameterAnalysis struct {
	AnalyzedParameters         []string `json:"analyzed_parameters"`          // Every query parameter name, sorted
	BrandKeywordsInURL         []string `json:"brand_keywords_in_url"`        // Brands named in the path or query but not the host
	CredentialParameters       []string `json:"credential_parameters"`        // Parameters named like a password or secret
	CredentialValuesPresent    bool     `json:"credential_values_present"`    // Whether any credential actually carries a value
	DangerousSchemeParameters  []string `json:"dangerous_scheme_parameters"`  // Parameters whose value is a javascript:, data: or similar URL
	DetectedPatterns           []string `json:"detected_patterns"`            // Every finding, worded for the report
	EmbeddedCredentials        bool     `json:"embedded_credentials"`         // Whether the URL has a user:password@ part
	EncodedPayloadParameters   []string `json:"encoded_payload_parameters"`   // Parameters hiding a base64 encoded URL or address
	ExternalRedirectParameters []string `json:"external_redirect_parameters"` // Redirect parameters pointing at another host
	IdentityParameters         []string `json:"identity_parameters"`          // Parameters pre-filling the victim's identity
	IsSuspicious               bool     `json:"is_suspicious"`                // Whether anything was found
	ParameterCount             int      `json:"parameter_count"`              // Distinct query parameter names
	SensitiveParameters        []string `json:"sensitive_parameters"`         // Parameters named like a card number or token
	StructuralIndicators       []string `json:"structural_indicators"`        // Shape findings: IP host, path keywords, length
	URL                        string   `json:"url"`                          // The URL with parameter values redacted
}

// Analyze performs the full phishing analysis of a URL.
func (a ParameterAnalyzer) Analyze(target *url.URL) ParameterAnalysis {
	host := strings.ToLower(strings.TrimSuffix(target.Hostname(), "."))
	query := target.Query()

	analysis := ParameterAnalysis{
		URL:            a.RedactURL(target),
		ParameterCount: len(query),
	}

	names := []string{}
	credentials := []string{}
	sensitive := []string{}
	identity := []string{}
	externalRedirects := []string{}
	encodedPayloads := []string{}
	dangerousSchemes := []string{}
	patterns := []string{}
	credentialValuePresent := false

	// Userinfo credentials are the most explicit form of credential exposure and
	// are additionally used to hide the real host behind an "@" in the URL.
	if target.User != nil && target.User.Username() != "" {
		analysis.EmbeddedCredentials = true
		patterns = append(patterns, "credentials embedded in the URL userinfo")
		if password, hasPassword := target.User.Password(); hasPassword && password != "" {
			credentialValuePresent = true
		}
	}

	for _, name := range sortedParameterNames(query) {
		names = append(names, name)

		if keyword, matched := matchesParameterDatabase(name, a.Credential); matched {
			credentials = append(credentials, name)
			if hasNonEmptyValue(query[name]) {
				credentialValuePresent = true
			}
			patterns = append(patterns, fmt.Sprintf("credential parameter %q (matches %q)", name, keyword))
		} else if keyword, matched := matchesParameterDatabase(name, a.Sensitive); matched {
			sensitive = append(sensitive, name)
			patterns = append(patterns, fmt.Sprintf("sensitive parameter %q (matches %q)", name, keyword))
		} else if _, matched := matchesParameterDatabase(name, a.Identity); matched {
			identity = append(identity, name)
			patterns = append(patterns, fmt.Sprintf("victim identity parameter %q", name))
		}

		_, isRedirectParameter := matchesParameterDatabase(name, a.Redirect)

		for _, value := range query[name] {
			if a.usesDangerousScheme(value) {
				dangerousSchemes = append(dangerousSchemes, name)
				patterns = append(patterns, fmt.Sprintf("parameter %q carries a dangerous scheme", name))
			}

			if isRedirectParameter && isExternalRedirectTarget(host, value) {
				externalRedirects = append(externalRedirects, name)
				patterns = append(patterns, fmt.Sprintf("redirect parameter %q points to an external host", name))
			}

			if payload, hidden := decodeHiddenPayload(value); hidden {
				encodedPayloads = append(encodedPayloads, name)
				patterns = append(patterns, fmt.Sprintf("parameter %q hides a base64 encoded %s", name, payload))
			}
		}
	}

	brands := a.detectBrandKeywordsOutsideHost(host, target)
	for _, brand := range brands {
		patterns = append(patterns, fmt.Sprintf("brand keyword %q used outside the hostname", brand))
	}

	structural := a.detectStructuralIndicators(host, target, len(query))
	patterns = append(patterns, structural...)

	analysis.CredentialValuesPresent = credentialValuePresent
	analysis.AnalyzedParameters = names
	analysis.CredentialParameters = SiteTests.UniqueStrings(credentials)
	analysis.SensitiveParameters = SiteTests.UniqueStrings(sensitive)
	analysis.IdentityParameters = SiteTests.UniqueStrings(identity)
	analysis.ExternalRedirectParameters = SiteTests.UniqueStrings(externalRedirects)
	analysis.EncodedPayloadParameters = SiteTests.UniqueStrings(encodedPayloads)
	analysis.DangerousSchemeParameters = SiteTests.UniqueStrings(dangerousSchemes)
	analysis.BrandKeywordsInURL = brands
	analysis.StructuralIndicators = structural
	analysis.DetectedPatterns = SiteTests.UniqueStrings(patterns)
	analysis.IsSuspicious = len(patterns) > 0

	return analysis
}

// EvaluateParameterThreat determines the security threat classification based on the
// indicators collected by Analyze.
func EvaluateParameterThreat(analysis ParameterAnalysis) SiteTests.ThreatLevel {
	if !analysis.IsSuspicious {
		return SiteTests.None
	}

	embedded := analysis.EmbeddedCredentials
	credentialValues := analysis.CredentialValuesPresent
	credentials := analysis.CredentialParameters
	sensitive := analysis.SensitiveParameters
	identity := analysis.IdentityParameters
	redirects := analysis.ExternalRedirectParameters
	encoded := analysis.EncodedPayloadParameters
	schemes := analysis.DangerousSchemeParameters
	brands := analysis.BrandKeywordsInURL
	structural := analysis.StructuralIndicators

	// Credentials travelling inside the URL or an executable scheme in a value
	// are unambiguous - no additional confirmation is required.
	if (embedded && credentialValues) || (len(credentials) > 0 && credentialValues) || len(schemes) > 0 {
		return SiteTests.Critical
	}

	highIndicators := len(credentials) + len(sensitive) + len(redirects) + len(encoded)
	if embedded {
		highIndicators++
	}

	// Several independent high severity indicators in a single URL describe a
	// fully assembled phishing link rather than a sloppy application.
	if highIndicators >= 3 {
		return SiteTests.Critical
	}

	if highIndicators > 0 {
		return SiteTests.High
	}

	// Weak indicators are individually inconclusive, but a link that pre-fills the
	// victim identity, borrows a brand name and uses an account-operation path at
	// the same time is the standard layout of a phishing landing page.
	weakIndicators := 0
	if len(identity) > 0 {
		weakIndicators++
	}
	if len(brands) > 0 {
		weakIndicators++
	}
	if containsStructuralIndicator(structural, "IP literal") {
		weakIndicators++
	}
	hasPhishingPath := containsStructuralIndicator(structural, "path keyword")

	// A phishing path keyword on its own is far too common in legitimate
	// applications to raise the level, so it only reinforces a brand mismatch.
	if weakIndicators >= 2 || (len(brands) > 0 && hasPhishingPath) {
		return SiteTests.High
	}

	if weakIndicators == 1 {
		return SiteTests.Medium
	}

	if len(structural) > 0 {
		return SiteTests.Low
	}

	return SiteTests.None
}

// DescribeParameters creates a human-readable summary of the analysis.
func DescribeParameters(analysis ParameterAnalysis) string {
	if !analysis.IsSuspicious {
		if analysis.ParameterCount == 0 {
			return "URL carries no query parameters and no phishing indicators were detected"
		}
		return fmt.Sprintf("No phishing indicators detected in the %d URL parameter(s)", analysis.ParameterCount)
	}

	sections := []string{}

	if analysis.EmbeddedCredentials {
		sections = append(sections, "credentials are embedded directly in the URL")
	}
	sections = appendParameterSection(sections, analysis.CredentialParameters, "credential parameter(s)")
	sections = appendParameterSection(sections, analysis.SensitiveParameters, "sensitive data parameter(s)")
	sections = appendParameterSection(sections, analysis.DangerousSchemeParameters, "parameter(s) with a dangerous scheme")
	sections = appendParameterSection(sections, analysis.ExternalRedirectParameters, "external redirect parameter(s)")
	sections = appendParameterSection(sections, analysis.EncodedPayloadParameters, "parameter(s) hiding encoded data")
	sections = appendParameterSection(sections, analysis.IdentityParameters, "victim identity parameter(s)")

	if brands := analysis.BrandKeywordsInURL; len(brands) > 0 {
		sections = append(sections, fmt.Sprintf("brand keyword(s) used outside the hostname: %s", strings.Join(brands, ", ")))
	}

	if structural := analysis.StructuralIndicators; len(structural) > 0 {
		sections = append(sections, strings.Join(structural, "; "))
	}

	return fmt.Sprintf(
		"Suspicious URL detected: %s. Analyzed URL: %s",
		strings.Join(sections, "; "),
		analysis.URL,
	)
}

// appendParameterSection appends a description fragment for one metadata category, but only
// when that category actually contains parameters.
func appendParameterSection(sections []string, values []string, label string) []string {
	if len(values) == 0 {
		return sections
	}
	return append(sections, fmt.Sprintf("%s: %s", label, strings.Join(values, ", ")))
}

// sortedParameterNames returns the query parameter names in a stable alphabetical order.
func sortedParameterNames(query url.Values) []string {
	names := make([]string, 0, len(query))
	for name := range query {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// matchesParameterDatabase checks whether a parameter name matches any entry of a parameter
// database.
func matchesParameterDatabase(name string, database []string) (string, bool) {
	normalized := normalizeParameterName(name)
	if normalized == "" {
		return "", false
	}

	for _, entry := range database {
		if normalized == entry {
			return entry, true
		}
		if len(entry) >= 4 && strings.Contains(normalized, entry) {
			return entry, true
		}
	}

	return "", false
}

// normalizeParameterName lowercases a parameter name and removes the separators commonly used
// to compose parameter names, so that different spellings of the same concept collapse into a
// single comparable form.
func normalizeParameterName(name string) string {
	replacer := strings.NewReplacer("_", "", "-", "", ".", "", "[", "", "]", "", " ", "")
	return replacer.Replace(strings.ToLower(strings.TrimSpace(name)))
}

// hasNonEmptyValue reports whether at least one of the values assigned to a parameter is non-
// empty.
func hasNonEmptyValue(values []string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return true
		}
	}
	return false
}

// usesDangerousScheme reports whether a parameter value starts with a scheme that allows
// script execution or inline payload delivery.
func (a ParameterAnalyzer) usesDangerousScheme(value string) bool {
	normalized := strings.ToLower(strings.TrimSpace(value))
	normalized = strings.NewReplacer("\t", "", "\n", "", "\r", "").Replace(normalized)

	for _, scheme := range a.DangerousSchemes {
		if strings.HasPrefix(normalized, scheme) {
			return true
		}
	}
	return false
}

// isExternalRedirectTarget reports whether a redirect parameter value points to a host
// different from the one being scanned.
func isExternalRedirectTarget(currentHost string, value string) bool {
	candidate := strings.TrimSpace(value)
	if strings.HasPrefix(candidate, "//") {
		candidate = "http:" + candidate
	}

	parsed, err := url.Parse(candidate)
	if err != nil || parsed.Host == "" {
		return false
	}

	targetHost := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	if targetHost == "" || targetHost == currentHost {
		return false
	}

	// Redirects between a host and its own subdomains stay inside the same site.
	return !strings.HasSuffix(targetHost, "."+currentHost) && !strings.HasSuffix(currentHost, "."+targetHost)
}

// decodeHiddenPayload detects base64 encoded content inside a parameter value.
func decodeHiddenPayload(value string) (string, bool) {
	decoded, ok := decodeBase64Candidate(value)
	if !ok {
		return "", false
	}

	lowered := strings.ToLower(decoded)
	if strings.Contains(lowered, "http://") || strings.Contains(lowered, "https://") || strings.HasPrefix(lowered, "//") {
		return "URL", true
	}

	if looksLikeEmailAddress(decoded) {
		return "e-mail address", true
	}

	return "", false
}

// decodeBase64Candidate attempts to decode a parameter value as base64 using the standard and
// URL-safe alphabets, in both padded and unpadded form.
func decodeBase64Candidate(value string) (string, bool) {
	trimmed := strings.TrimSpace(value)
	if len(trimmed) < 16 || len(trimmed) > 2048 {
		return "", false
	}

	if strings.ContainsAny(trimmed, " \t\r\n") {
		return "", false
	}

	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}

	for _, encoding := range encodings {
		decoded, err := encoding.DecodeString(trimmed)
		if err != nil {
			continue
		}
		if !isMostlyPrintable(string(decoded)) {
			continue
		}
		return string(decoded), true
	}

	return "", false
}

// isMostlyPrintable reports whether a decoded string consists predominantly of printable ASCII
// characters.
func isMostlyPrintable(s string) bool {
	if s == "" {
		return false
	}

	printable := 0
	for _, r := range s {
		if r >= 0x20 && r <= 0x7E {
			printable++
		}
	}

	return printable*10 >= len(s)*9
}

// looksLikeEmailAddress performs a lightweight check for an e-mail address.
func looksLikeEmailAddress(value string) bool {
	candidate := strings.TrimSpace(value)
	if strings.ContainsAny(candidate, " \t\r\n") {
		return false
	}

	at := strings.Index(candidate, "@")
	if at <= 0 || at == len(candidate)-1 || strings.Count(candidate, "@") != 1 {
		return false
	}

	domain := candidate[at+1:]
	dot := strings.LastIndex(domain, ".")

	return dot > 0 && dot < len(domain)-1
}

// detectBrandKeywordsOutsideHost finds popular brand names placed in the path or query of a
// URL whose hostname has nothing to do with that brand.
func (a ParameterAnalyzer) detectBrandKeywordsOutsideHost(host string, target *url.URL) []string {
	haystack := strings.ToLower(target.EscapedPath() + "?" + target.RawQuery)
	found := []string{}

	for _, brand := range a.Brands {
		if len(brand) < a.MinBrandKeywordLength {
			continue
		}
		if strings.Contains(host, brand) {
			continue
		}
		if SiteTests.ContainsStandaloneToken(haystack, brand) {
			found = append(found, brand)
		}
	}

	sort.Strings(found)
	return found
}

// detectStructuralIndicators collects anomalies in the overall shape of the URL.
func (a ParameterAnalyzer) detectStructuralIndicators(host string, target *url.URL, parameterCount int) []string {
	indicators := []string{}

	if net.ParseIP(host) != nil {
		indicators = append(indicators, "IP literal used instead of a hostname")
	}

	keywords := []string{}
	path := strings.ToLower(target.EscapedPath())
	for _, keyword := range a.PathKeywords {
		if SiteTests.ContainsStandaloneToken(path, keyword) {
			keywords = append(keywords, keyword)
		}
	}
	if len(keywords) > 0 {
		indicators = append(indicators, fmt.Sprintf("phishing-style path keyword(s): %s", strings.Join(keywords, ", ")))
	}

	if len(target.RawQuery) > a.MaxQueryLength {
		indicators = append(indicators, fmt.Sprintf("query string is unusually long (%d characters)", len(target.RawQuery)))
	}

	if parameterCount > a.MaxParameterCount {
		indicators = append(indicators, fmt.Sprintf("unusually many query parameters (%d)", parameterCount))
	}

	return indicators
}

// containsStructuralIndicator reports whether any structural indicator contains a given
// fragment.
func containsStructuralIndicator(indicators []string, fragment string) bool {
	for _, indicator := range indicators {
		if strings.Contains(indicator, fragment) {
			return true
		}
	}
	return false
}

// RedactURL renders the analyzed URL with every secret removed, so the finding can be stored
// and displayed without leaking the credentials it reports.
func (a ParameterAnalyzer) RedactURL(target *url.URL) string {
	redacted := *target
	redacted.User = nil
	redacted.RawQuery = a.redactedQuery(target)

	rendered := redacted.String()
	if target.User != nil {
		if separator := strings.Index(rendered, "//"); separator >= 0 {
			insert := separator + len("//")
			rendered = rendered[:insert] + a.RedactedPlaceholder + "@" + rendered[insert:]
		}
	}

	return rendered
}

// redactedQuery renders the query string with the values of credential and sensitive
// parameters replaced by the redaction placeholder.
func (a ParameterAnalyzer) redactedQuery(target *url.URL) string {
	query := target.Query()
	if len(query) == 0 {
		return ""
	}

	pairs := []string{}
	for _, name := range sortedParameterNames(query) {
		_, isCredential := matchesParameterDatabase(name, a.Credential)
		_, isSensitive := matchesParameterDatabase(name, a.Sensitive)

		for _, value := range query[name] {
			if isCredential || isSensitive {
				pairs = append(pairs, url.QueryEscape(name)+"="+a.RedactedPlaceholder)
				continue
			}
			pairs = append(pairs, url.QueryEscape(name)+"="+url.QueryEscape(value))
		}
	}

	return strings.Join(pairs, "&")
}
