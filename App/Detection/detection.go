// Package Detection identifies bot protection and CDN/WAF layers sitting in front of a
// target. It is shared by the HTTP transport, which annotates its results with what it
// saw, and by the bot-protection security test, which probes a target on its own.
//
// The package draws a deliberate line between two very different findings:
//
//   - Presence: the target is served through a CDN or WAF. Headers such as Server:
//     cloudflare, CF-RAY or CF-Cache-Status appear on every Cloudflare-proxied response,
//     including a perfectly reachable one, so presence alone says nothing about whether
//     the scan was obstructed. It never blocks anything.
//   - Challenge: the target actually served an interstitial instead of its content.
//     Only this justifies skipping tests that need the page body.
//
// Conflating the two is what made any Cloudflare-fronted target unscannable: a single
// CF-RAY header on a healthy 200 response was enough to abort the whole run.
package Detection

import (
	helpers "Engine-AntiGinx/App/Helpers"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// probeTimeout bounds a single detection probe. Protection layers that intend to
// challenge a client answer fast; a slow target is a connectivity problem, not a verdict.
const probeTimeout = 15 * time.Second

// maxProbeBody caps how much of a response body is scanned for fingerprints.
// Interstitial pages are small, and every marker of interest lives near the top.
const maxProbeBody = 512 * 1024

// probeUserAgent is a plain browser User-Agent. The probe deliberately does not try to
// evade detection: its job is to observe how the target treats an ordinary visitor.
const probeUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
	"(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

// presenceHeaders maps a response header to the vendor it identifies. A hit means the
// target is served through that vendor's infrastructure, nothing more.
var presenceHeaders = map[string]string{
	"CF-RAY":               "Cloudflare Ray ID",
	"CF-Cache-Status":      "Cloudflare Cache",
	"X-Iinfo":              "Incapsula Protection",
	"X-CDN":                "Incapsula Protection",
	"X-Datadome":           "DataDome",
	"X-DataDome-CID":       "DataDome",
	"X-Px":                 "PerimeterX",
	"X-Sucuri-ID":          "Sucuri Firewall",
	"X-Akamai-Transformed": "Akamai",
}

// challengeHeaders maps a response header to the vendor whose challenge it signals.
// Unlike presenceHeaders these are only ever set when the request was actively mitigated.
var challengeHeaders = map[string]string{
	"CF-CHL-BCODE": "Cloudflare Challenge",
	"CF-Mitigated": "Cloudflare Mitigation",
}

// presenceMarkers maps a body fragment to the vendor it identifies. These appear in the
// markup of normally served pages — a bot management cookie name, a vendor script host —
// so they are evidence of a protection layer, not of an obstructed scan.
var presenceMarkers = map[string]string{
	"__cf_bm":                     "Cloudflare Bot Management",
	"/cdn-cgi/challenge-platform": "Cloudflare Challenge Platform",
	"_incapsula_resource":         "Incapsula Protection",
	"incapsula":                   "Incapsula Protection",
	"distil":                      "Distil Networks",
	"perimeterx":                  "PerimeterX",
	"datadome":                    "DataDome",
	"reblaze":                     "Reblaze",
	"radware":                     "Radware",
}

// challengeMarkers maps a body fragment to the challenge it identifies. Every entry is a
// structural artefact that only an interstitial page carries, so a hit counts as a
// challenge regardless of the status code.
//
// The bar for membership here is high, and deliberately excludes fragments that a vendor
// also injects into healthy pages. /cdn-cgi/challenge-platform is the instructive case:
// Cloudflare adds its script to ordinary 200 responses for passive JavaScript detection,
// so treating it as a challenge would mark a perfectly reachable site as blocked. It lives
// in presenceMarkers instead. Modern challenges answer with 403 or 503 anyway, which the
// status-gated keyword path already covers.
var challengeMarkers = map[string]string{
	"cf-browser-verification":                "Cloudflare Browser Verification",
	"attention required! | cloudflare":       "Cloudflare Block Page",
	"checking your browser before accessing": "Cloudflare Interstitial",
	"px-captcha":                             "PerimeterX Captcha",
	"geo.captcha-delivery.com":               "DataDome Captcha",
}

// challengeKeywords are weak, human-language hints of a block. They routinely appear in
// legitimate content — an article about Cloudflare, a page with a contact-form captcha —
// so they are only trusted when the target already refused to serve its content, that is
// when the status code is not 200.
var challengeKeywords = []string{
	"captcha", "attention required", "verify you are human",
	"security check", "ddos protection", "access denied",
	"suspicious activity", "bot detected", "automated traffic",
	"rate limited", "javascript is required", "browser check",
	"enable javascript and cookies to continue",
}

// Report is the outcome of inspecting one response for protection layers.
//
// Fields:
//   - Presence: Vendors identified in front of the target, harmless on their own
//   - Challenge: Evidence that content was withheld behind an interstitial
//   - StatusCode: Status code of the inspected response, 0 when none was obtained
type Report struct {
	Presence   []string `json:"Presence,omitempty"`
	Challenge  []string `json:"Challenge,omitempty"`
	StatusCode int      `json:"StatusCode"`
}

// IsBlocked reports whether the target withheld its content behind a challenge.
// This is the only condition under which tests requiring a page body should be skipped.
//
// Returns:
//   - bool: true when at least one challenge indicator was found
func (r Report) IsBlocked() bool { return len(r.Challenge) > 0 }

// HasProtection reports whether any protection layer was identified at all,
// whether or not it obstructed the scan.
//
// Returns:
//   - bool: true when either presence or challenge indicators were found
func (r Report) HasProtection() bool { return len(r.Presence) > 0 || len(r.Challenge) > 0 }

// All returns every indicator found, challenges first, for reporting purposes.
//
// Returns:
//   - []string: Combined challenge and presence indicators, nil when none were found
func (r Report) All() []string {
	if !r.HasProtection() {
		return nil
	}
	combined := make([]string, 0, len(r.Challenge)+len(r.Presence))
	combined = append(combined, r.Challenge...)
	combined = append(combined, r.Presence...)
	return combined
}

// FromResponse inspects an already-obtained response and its body for protection layers.
// The body is passed separately because callers have usually consumed and restored it.
//
// Parameters:
//   - resp: The response to inspect, may be nil
//   - body: The response body as text, may be empty when it was not read
//
// Returns:
//   - Report: Presence and challenge indicators found, empty when resp is nil
func FromResponse(resp *http.Response, body string) Report {
	if resp == nil {
		return Report{}
	}
	report := Report{StatusCode: resp.StatusCode}
	lowerBody := strings.ToLower(body)

	report.Presence = append(report.Presence, presenceFromHeaders(resp.Header)...)
	report.Presence = append(report.Presence, markersIn(lowerBody, presenceMarkers)...)

	report.Challenge = append(report.Challenge, challengeFromHeaders(resp.Header)...)
	report.Challenge = append(report.Challenge, markersIn(lowerBody, challengeMarkers)...)
	if resp.StatusCode != http.StatusOK {
		report.Challenge = append(report.Challenge, keywordsIn(lowerBody)...)
	}

	report.Presence = helpers.RemoveDuplicates(report.Presence)
	report.Challenge = helpers.RemoveDuplicates(report.Challenge)
	return report
}

// Probe performs an independent request against the target and reports what protection
// layers front it. It is used by the bot-protection test, which must reach a verdict
// without depending on the main scan request having succeeded.
//
// Unlike the scanner's HTTP wrapper, Probe never panics and treats a non-200 status as
// data rather than as an error: a 403 challenge page is precisely what it looks for.
//
// Parameters:
//   - target: The URL to probe
//
// Returns:
//   - Report: Indicators found at the target
//   - error: Non-nil only when the target could not be reached at all
func Probe(target *url.URL) (Report, error) {
	if target == nil {
		return Report{}, fmt.Errorf("no target provided")
	}

	req, err := http.NewRequest(http.MethodGet, target.String(), nil)
	if err != nil {
		return Report{}, fmt.Errorf("failed to build probe request: %w", err)
	}
	req.Header.Set("User-Agent", probeUserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")

	client := &http.Client{Timeout: probeTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return Report{}, fmt.Errorf("probe request failed: %w", err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			fmt.Printf("Detection \nWarning: Failed to close response body: %s", cerr.Error())
		}
	}()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxProbeBody))
	if err != nil {
		// A truncated body still carries usable header evidence, so the headers are
		// reported rather than discarding the probe entirely.
		return FromResponse(resp, ""), nil
	}
	return FromResponse(resp, string(body)), nil
}

// FormatList renders indicators as a numbered, human-readable list for messages and
// descriptions.
//
// Parameters:
//   - items: Indicators to render
//
// Returns:
//   - string: Numbered list, one indicator per line, empty when items is empty
func FormatList(items []string) string {
	var builder strings.Builder
	for i, item := range items {
		builder.WriteString(fmt.Sprintf("  %d. %s\n", i+1, item))
	}
	return builder.String()
}

// presenceFromHeaders collects vendor fingerprints from response headers.
//
// Parameters:
//   - header: Response headers to inspect
//
// Returns:
//   - []string: Presence indicators, nil when none matched
func presenceFromHeaders(header http.Header) []string {
	var found []string
	if strings.EqualFold(header.Get("Server"), "cloudflare") {
		found = append(found, "Cloudflare Server")
	}
	for name, vendor := range presenceHeaders {
		if value := header.Get(name); value != "" {
			found = append(found, vendor+": "+value)
		}
	}
	return found
}

// challengeFromHeaders collects headers that are only set when a request was mitigated.
//
// Parameters:
//   - header: Response headers to inspect
//
// Returns:
//   - []string: Challenge indicators, nil when none matched
func challengeFromHeaders(header http.Header) []string {
	var found []string
	for name, vendor := range challengeHeaders {
		if header.Get(name) != "" {
			found = append(found, vendor)
		}
	}
	return found
}

// markersIn collects the labels of every marker present in an already-lowercased body.
//
// Parameters:
//   - lowerBody: Response body, lowercased by the caller
//   - markers: Marker fragment to label mapping
//
// Returns:
//   - []string: Labels of matched markers, nil when none matched
func markersIn(lowerBody string, markers map[string]string) []string {
	if lowerBody == "" {
		return nil
	}
	var found []string
	for marker, label := range markers {
		if strings.Contains(lowerBody, marker) {
			found = append(found, label)
		}
	}
	return found
}

// keywordsIn collects weak challenge keywords present in an already-lowercased body.
// Callers must only apply it to responses that did not return 200.
//
// Parameters:
//   - lowerBody: Response body, lowercased by the caller
//
// Returns:
//   - []string: Descriptions of matched keywords, nil when none matched
func keywordsIn(lowerBody string) []string {
	if lowerBody == "" {
		return nil
	}
	var found []string
	for _, keyword := range challengeKeywords {
		if strings.Contains(lowerBody, keyword) {
			found = append(found, "Content contains: "+keyword)
		}
	}
	return found
}
