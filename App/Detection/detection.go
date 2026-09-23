// Package Detection distinguishes protection-layer presence from active challenges.
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

// probeTimeout bounds the independent detection request.
const probeTimeout = 15 * time.Second

// maxProbeBody limits how much of the response is inspected for markers.
const maxProbeBody = 512 * 1024

// probeUserAgent represents an ordinary browser; probing does not attempt evasion.
const probeUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
	"(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

// presenceHeaders identifies a vendor without implying a blocked request.
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

// challengeHeaders identifies active mitigation headers.
var challengeHeaders = map[string]string{
	"CF-CHL-BCODE": "Cloudflare Challenge",
	"CF-Mitigated": "Cloudflare Mitigation",
}

// presenceMarkers may also occur in normally served pages.
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

// challengeMarkers identifies interstitials regardless of status code.
// /cdn-cgi/challenge-platform belongs in presenceMarkers: it also occurs on healthy pages.
var challengeMarkers = map[string]string{
	"cf-browser-verification":                "Cloudflare Browser Verification",
	"attention required! | cloudflare":       "Cloudflare Block Page",
	"checking your browser before accessing": "Cloudflare Interstitial",
	"px-captcha":                             "PerimeterX Captcha",
	"geo.captcha-delivery.com":               "DataDome Captcha",
}

// challengeKeywords require a non-200 response to avoid false positives on normal pages.
var challengeKeywords = []string{
	"captcha", "attention required", "verify you are human",
	"security check", "ddos protection", "access denied",
	"suspicious activity", "bot detected", "automated traffic",
	"rate limited", "javascript is required", "browser check",
	"enable javascript and cookies to continue",
}

// Report separates protection presence from challenge evidence for one response.
type Report struct {
	Presence   []string `json:"Presence,omitempty"`
	Challenge  []string `json:"Challenge,omitempty"`
	StatusCode int      `json:"StatusCode"`
}

// IsBlocked reports whether any challenge indicator was found.
func (r Report) IsBlocked() bool { return len(r.Challenge) > 0 }

// HasProtection reports whether any presence or challenge indicator was found.
func (r Report) HasProtection() bool { return len(r.Presence) > 0 || len(r.Challenge) > 0 }

// All returns challenge indicators followed by presence indicators, or nil if empty.
func (r Report) All() []string {
	if !r.HasProtection() {
		return nil
	}
	combined := make([]string, 0, len(r.Challenge)+len(r.Presence))
	combined = append(combined, r.Challenge...)
	combined = append(combined, r.Presence...)
	return combined
}

// FromResponse inspects a response and separately supplied body for protection indicators.
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

// Probe makes an independent request and inspects its response, including non-200 statuses.
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

// FormatList renders indicators as a numbered list, one per line.
func FormatList(items []string) string {
	var builder strings.Builder
	for i, item := range items {
		fmt.Fprintf(&builder, "  %d. %s\n", i+1, item)
	}
	return builder.String()
}

// presenceFromHeaders collects vendor fingerprints from response headers.
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

// challengeFromHeaders collects mitigation indicators from response headers.
func challengeFromHeaders(header http.Header) []string {
	var found []string
	for name, vendor := range challengeHeaders {
		if header.Get(name) != "" {
			found = append(found, vendor)
		}
	}
	return found
}

// markersIn collects matching labels from an already-lowercased body.
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

// keywordsIn collects weak challenge hints; callers must gate it on non-200 status.
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
