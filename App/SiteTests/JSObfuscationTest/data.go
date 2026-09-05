package JSObfuscationTest

import (
	"regexp"

	"Engine-AntiGinx/App/SiteTests/JSObfuscationTest/modules"
)

// obfuscationPatterns are every expression the detectors match against, compiled once at start
// up.
var obfuscationPatterns = modules.Patterns{
	Script: regexp.MustCompile(`(?is)<script[^>]*>(.*?)</script>`),

	// String-to-code entry points. The map key is the name reported for the finding.
	DynamicExecution: map[string]*regexp.Regexp{
		"eval":        regexp.MustCompile(`\beval\s*\(`),
		"Function":    regexp.MustCompile(`\bFunction\s*\(`),
		"setTimeout":  regexp.MustCompile(`setTimeout\s*\(\s*["']`),
		"setInterval": regexp.MustCompile(`setInterval\s*\(\s*["']`),
	},

	EvalOfDecoder:      regexp.MustCompile(`eval\s*\(\s*(?:atob|unescape|decodeURI|String\.fromCharCode)`),
	Atob:               regexp.MustCompile(`atob\s*\(`),
	Unescape:           regexp.MustCompile(`\b(?:unescape|decodeURI|decodeURIComponent)\s*\(`),
	CharCode:           regexp.MustCompile(`String\.fromCharCode\s*\(`),
	LargeCharCodeArray: regexp.MustCompile(`String\.fromCharCode\s*\([^)]{100,}\)`),
	HexEscape:          regexp.MustCompile(`\\x[0-9a-fA-F]{2}`),
	UnicodeEscape:      regexp.MustCompile(`\\u[0-9a-fA-F]{4}`),
	Base64Literal:      regexp.MustCompile(`["'][A-Za-z0-9+/]{40,}={0,2}["']`),
	StringConcat:       regexp.MustCompile(`['"]\s*\+\s*['"]`),
	BracketAccess:      regexp.MustCompile(`\w+\["(?:eval|Function|setTimeout|setInterval)"\]`),
	HexArray:           regexp.MustCompile(`\[(?:\s*0x[0-9a-fA-F]+\s*,?){10,}\]`),
	MultilayerDecode:   regexp.MustCompile(`(?:atob|unescape|decodeURI)\s*\(\s*(?:atob|unescape|decodeURI)`),

	// Words that speak to intent rather than to technique. Obfuscation hides how a script
	// works; these suggest what it is for.
	SuspiciousKeywords: []string{"shell", "cmd", "exec", "payload", "exploit", "backdoor"},
}
