package modules

import (
	"Engine-AntiGinx/App/SiteTests"
	"regexp"
	"strings"
)

// maxEndpointLength caps how much of an endpoint found in a script is reported.
const maxEndpointLength = 160

// ScriptPatterns are the compiled expressions scripts are inspected with.
type ScriptPatterns struct {
	Sender    *regexp.Regexp // A call that sends data over the network
	ValueRead *regexp.Regexp // A read of what was typed into a field
}

// ScriptSubmission is one inline script that sends data to a data-collection service.
type ScriptSubmission struct {
	Script           int      `json:"Script"` // Position among the page's inline scripts
	Provider         string   `json:"Provider"`
	CollectorKind    string   `json:"CollectorKind"`
	Endpoint         string   `json:"Endpoint"`
	Senders          []string `json:"Senders"`
	ReadsFieldValues bool     `json:"ReadsFieldValues"`
}

// ScriptInspector finds inline scripts that send data to a data-collection service.
type ScriptInspector struct {
	Patterns   ScriptPatterns
	Collectors []Collector
}

// Inspect reports every collector one script sends to. A script that names a collector but
// makes no network call is not reported: the page may only be linking to the service.
func (s ScriptInspector) Inspect(index int, script string) []ScriptSubmission {
	submissions := []ScriptSubmission{}

	senders := []string{}
	for _, sender := range s.Patterns.Sender.FindAllString(script, -1) {
		senders = append(senders, strings.Join(strings.Fields(sender), ""))
	}
	senders = SiteTests.UniqueStrings(senders)
	if len(senders) == 0 {
		return submissions
	}

	// JSON-encoded strings escape the slashes of the URLs they carry.
	unescaped := strings.ReplaceAll(script, `\/`, "/")
	lowered := strings.ToLower(unescaped)
	if len(lowered) != len(unescaped) {
		unescaped = lowered // Positions only carry over while lowercasing keeps every byte in place
	}
	readsValues := s.Patterns.ValueRead.MatchString(script)
	seen := map[string]bool{}
	for _, collector := range s.Collectors {
		marker := strings.ToLower(collector.Marker())
		position := strings.Index(lowered, marker)
		if position < 0 || seen[collector.Name] {
			continue
		}
		seen[collector.Name] = true
		submissions = append(submissions, ScriptSubmission{
			Script:           index,
			Provider:         collector.Name,
			CollectorKind:    collector.Kind,
			Endpoint:         endpointAround(unescaped, position, len(marker)),
			Senders:          senders,
			ReadsFieldValues: readsValues,
		})
	}
	return submissions
}

// endpointAround widens a marker found in a script to the whole URL-like run of characters it
// sits in, so a subdomain before it and a path after it are reported too.
func endpointAround(script string, start int, length int) string {
	end := start + length
	for start > 0 && isHostCharacter(script[start-1]) {
		start--
	}
	for end < len(script) && isURLCharacter(script[end]) {
		end++
	}
	endpoint := script[start:end]
	if len(endpoint) > maxEndpointLength {
		endpoint = endpoint[:maxEndpointLength] + "…"
	}
	return endpoint
}

// isHostCharacter reports whether a byte can be part of a hostname.
func isHostCharacter(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-'
}

// isURLCharacter reports whether a byte can be part of a URL written without quotes around it.
func isURLCharacter(c byte) bool {
	return isHostCharacter(c) || strings.IndexByte("_~:/?#[]@!$&*+,;=%", c) >= 0
}
