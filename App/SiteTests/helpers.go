package SiteTests

import (
	"net"
	"strconv"
	"strings"
)

// NormalizeHeaderValue trims a header value and lowercases it for comparison.
func NormalizeHeaderValue(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

// SplitHeaderList splits a header on a separator, trimming each part and dropping empties.
func SplitHeaderList(header string, separator string) []string {
	parts := []string{}
	for _, part := range strings.Split(header, separator) {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			parts = append(parts, trimmed)
		}
	}
	return parts
}

// ParseDirectives parses a semicolon-separated directive header into directive names mapped
// to their values. Names are lowercased; the first occurrence of a repeated directive wins,
// which is how browsers resolve one.
func ParseDirectives(header string) map[string][]string {
	directives := map[string][]string{}
	for _, directive := range SplitHeaderList(header, ";") {
		fields := strings.Fields(directive)
		if len(fields) == 0 {
			continue
		}
		name := strings.ToLower(fields[0])
		if _, exists := directives[name]; !exists {
			directives[name] = fields[1:]
		}
	}
	return directives
}

// DirectiveValue returns one directive's values as they were written, and whether the
// directive was present at all — a directive present with no values is not the same as an
// absent one.
func DirectiveValue(header string, name string) (string, bool) {
	values, present := ParseDirectives(header)[strings.ToLower(name)]
	if !present {
		return "", false
	}
	return strings.Join(values, " "), true
}

// ContainsAnyFold reports whether the haystack contains any of the needles, ignoring case.
func ContainsAnyFold(haystack string, needles []string) bool {
	return len(FindAllFold(haystack, needles)) > 0
}

// FindAllFold returns every needle the haystack contains, ignoring case, in the order the
// needles were given.
func FindAllFold(haystack string, needles []string) []string {
	lowered := strings.ToLower(haystack)
	found := []string{}
	for _, needle := range needles {
		if needle != "" && strings.Contains(lowered, strings.ToLower(needle)) {
			found = append(found, needle)
		}
	}
	return found
}

// ContainsStandaloneToken reports whether a token appears in the haystack delimited by
// non-alphanumeric characters, so "google" does not match inside "googleapis".
func ContainsStandaloneToken(haystack string, token string) bool {
	offset := 0
	for {
		index := strings.Index(haystack[offset:], token)
		if index < 0 {
			return false
		}

		start := offset + index
		end := start + len(token)
		if !isAlphanumericAt(haystack, start-1) && !isAlphanumericAt(haystack, end) {
			return true
		}

		offset = start + 1
		if offset >= len(haystack) {
			return false
		}
	}
}

// isAlphanumericAt reports whether the byte at an index is a letter or digit. Positions
// outside the string count as delimiters.
func isAlphanumericAt(s string, index int) bool {
	if index < 0 || index >= len(s) {
		return false
	}
	c := s[index]
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// UniqueStrings removes repeated values while preserving the order they first appeared in.
func UniqueStrings(values []string) []string {
	seen := map[string]struct{}{}
	unique := make([]string, 0, len(values))
	for _, value := range values {
		if _, repeated := seen[value]; repeated {
			continue
		}
		seen[value] = struct{}{}
		unique = append(unique, value)
	}
	return unique
}

// HighestThreatLevel returns the most severe of the levels given, or None when given none.
func HighestThreatLevel(levels ...ThreatLevel) ThreatLevel {
	highest := None
	for _, level := range levels {
		if level > highest {
			highest = level
		}
	}
	return highest
}

// EscalateThreatLevel raises a level by one, capped at Critical. It is how a test says that
// several independent findings together mean more than the worst of them alone.
func EscalateThreatLevel(level ThreatLevel) ThreatLevel {
	if level >= Critical {
		return Critical
	}
	return level + 1
}

// FormatDuration renders a number of seconds as the largest whole unit that fits.
func FormatDuration(seconds int) string {
	units := []struct {
		size     int
		singular string
		plural   string
	}{
		{60 * 60 * 24 * 365, "year", "years"},
		{60 * 60 * 24 * 30, "month", "months"},
		{60 * 60 * 24, "day", "days"},
		{60 * 60, "hour", "hours"},
	}

	for _, unit := range units {
		if seconds < unit.size {
			continue
		}
		count := seconds / unit.size
		if count == 1 {
			return "1 " + unit.singular
		}
		return strconv.Itoa(count) + " " + unit.plural
	}
	return strconv.Itoa(seconds) + " seconds"
}

// RegistrableDomain reduces a hostname to the domain somebody registered, so two hostnames
// can be compared as belonging to the same site. IP addresses are returned unchanged.
func RegistrableDomain(host string) string {
	host = strings.ToLower(strings.Trim(strings.TrimSpace(host), "."))
	if host == "" || net.ParseIP(host) != nil {
		return host
	}

	labels := strings.Split(host, ".")
	if len(labels) < 3 {
		return host
	}

	lastTwo := strings.Join(labels[len(labels)-2:], ".")
	if multiLabelPublicSuffixes[lastTwo] {
		return strings.Join(labels[len(labels)-3:], ".")
	}
	return lastTwo
}

// multiLabelPublicSuffixes are the public suffixes made of more than one label that the engine
// recognises locally, so that a hostname under one of them is reduced to the domain somebody
// actually registered rather than to the suffix itself.
var multiLabelPublicSuffixes = map[string]bool{
	"co.uk": true, "org.uk": true, "ac.uk": true, "gov.uk": true, "me.uk": true, "net.uk": true, "sch.uk": true,
	"com.pl": true, "net.pl": true, "org.pl": true, "edu.pl": true, "gov.pl": true, "info.pl": true, "waw.pl": true, "com.au": true,
	"net.au": true, "org.au": true, "edu.au": true, "gov.au": true, "id.au": true,
	"com.br": true, "net.br": true, "org.br": true, "gov.br": true,
	"com.cn": true, "net.cn": true, "org.cn": true, "gov.cn": true, "edu.cn": true,
	"co.jp": true, "or.jp": true, "ne.jp": true, "ac.jp": true, "go.jp": true,
	"co.kr": true, "or.kr": true, "co.in": true, "net.in": true, "org.in": true, "gov.in": true,
	"co.za": true, "org.za": true, "co.nz": true, "net.nz": true, "org.nz": true, "govt.nz": true,
	"com.mx": true, "com.ar": true, "com.co": true, "com.tr": true, "gov.tr": true, "com.ua": true,
	"com.sg": true, "com.hk": true, "com.tw": true, "com.my": true, "com.ph": true, "com.vn": true,
	"co.il": true, "co.id": true, "com.sa": true, "com.eg": true, "com.ng": true, "com.pk": true,
	"co.th": true, "in.th": true, "com.es": true, "com.pt": true, "com.gr": true, "com.ro": true,
	"com.ru": true, "org.ru": true, "net.ru": true, "com.de": true, "com.it": true,
}
