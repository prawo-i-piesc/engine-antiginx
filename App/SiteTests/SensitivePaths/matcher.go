package SensitivePaths

import "strings"

// Merge copies pattern tables into one, later tables overriding earlier ones on a shared
// key. Tests pass them in rising order of specificity, so their own wording wins.
func Merge(tables ...map[string]string) map[string]string {
	merged := make(map[string]string)
	for _, table := range tables {
		for pattern, category := range table {
			merged[pattern] = category
		}
	}
	return merged
}

// Matcher is a pattern-to-category table that a declared path is matched against.
type Matcher map[string]string

// Best returns the longest pattern the path contains, so /api-docs is reported as API
// documentation rather than as an API endpoint. Ties go to the pattern that sorts first,
// which keeps the result independent of map order.
func (m Matcher) Best(path string) (string, string, bool) {
	lowered := strings.ToLower(path)
	best := ""
	for pattern := range m {
		if !containsPathFragment(lowered, pattern) {
			continue
		}
		if len(pattern) > len(best) || (len(pattern) == len(best) && pattern < best) {
			best = pattern
		}
	}
	if best == "" {
		return "", "", false
	}
	return best, m[best], true
}

// containsPathFragment reports whether a fragment occurs in the path and is not followed by
// a letter, so /test matches /test/, /test.php and /test2 but not /testimonials.
func containsPathFragment(path string, fragment string) bool {
	if fragment == "" {
		return false
	}
	offset := 0
	for {
		index := strings.Index(path[offset:], fragment)
		if index < 0 {
			return false
		}
		end := offset + index + len(fragment)
		if end >= len(path) || !isLetter(path[end]) {
			return true
		}
		offset += index + 1
	}
}

// isLetter reports whether a byte is an ASCII letter.
func isLetter(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}
