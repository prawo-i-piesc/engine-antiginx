// Package modules holds the stage implementations of the URLhaus Malicious URL Lookup test.
// It is used by its own core.go and nothing else.
package modules

import (
	"Engine-AntiGinx/App/SiteTests"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

// URLhaus query_status values the test understands; anything else is a failed lookup.
const (
	queryStatusOK        = "ok"
	queryStatusNoResults = "no_results"
	urlStatusOnline      = "online"
	surblListed          = "listed"
)

// Lookup queries the URLhaus API about a target.
type Lookup struct {
	HTTPClient       *http.Client
	BaseURL          string
	AuthKey          string
	MaxResponseSize  int64
	MaxReportedURLs  int
	AbusedLegitimate []string
	Malicious        []string
}

// URLhausEntry is one URL as URLhaus records it.
type URLhausEntry struct {
	URL       string   `json:"url"`
	Status    string   `json:"url_status"`
	Threat    string   `json:"threat"`
	Tags      []string `json:"tags"`
	DateAdded string   `json:"date_added"`
	Reference string   `json:"urlhaus_reference"`
}

// URLhausBlacklists are the third-party listings URLhaus reports for a host.
type URLhausBlacklists struct {
	SpamhausDBL string `json:"spamhaus_dbl"`
	SURBL       string `json:"surbl"`
}

// URLhausMetadata is everything the lookup established about the target.
type URLhausMetadata struct {
	Checked     bool   `json:"checked"`
	LookupError string `json:"lookup_error,omitempty"`
	URL         string `json:"url"`
	Host        string `json:"host"`

	URLListed bool          `json:"url_listed"`
	URLEntry  *URLhausEntry `json:"url_entry,omitempty"`

	HostListed       bool              `json:"host_listed"`
	HostReference    string            `json:"host_reference,omitempty"`
	HostURLCount     int               `json:"host_url_count"`
	HostOnlineURLs   int               `json:"host_online_urls"`
	HostURLs         []URLhausEntry    `json:"host_urls"`
	Blacklists       URLhausBlacklists `json:"blacklists"`
	AbusedLegitimate bool              `json:"abused_legitimate"`
	MaliciousListing bool              `json:"malicious_listing"`
}

// urlResponse is the subset of a /v1/url/ answer the test reads.
type urlResponse struct {
	QueryStatus string `json:"query_status"`
	URLhausEntry
}

// hostResponse is the subset of a /v1/host/ answer the test reads.
type hostResponse struct {
	QueryStatus string            `json:"query_status"`
	Reference   string            `json:"urlhaus_reference"`
	URLCount    flexibleInt       `json:"url_count"`
	Blacklists  URLhausBlacklists `json:"blacklists"`
	URLs        []URLhausEntry    `json:"urls"`
}

// flexibleInt decodes a count URLhaus sends as a string ("120") as well as a number.
type flexibleInt int

// UnmarshalJSON accepts both a JSON number and a quoted number.
func (n *flexibleInt) UnmarshalJSON(data []byte) error {
	text := strings.Trim(string(data), `"`)
	if text == "" || text == "null" {
		*n = 0
		return nil
	}
	value, err := strconv.Atoi(text)
	if err != nil {
		return err
	}
	*n = flexibleInt(value)
	return nil
}

// Check looks the target URL and its host up. A failure of either lookup is recorded in the
// metadata and leaves Checked false, because a half answer must not read as a clean one.
func (l Lookup) Check(target *url.URL) URLhausMetadata {
	metadata := URLhausMetadata{HostURLs: []URLhausEntry{}}
	if target == nil || target.Hostname() == "" {
		metadata.LookupError = "target has no hostname"
		return metadata
	}

	// Credentials and fragments never leave the engine; the rest is what URLhaus indexes.
	queried := *target
	queried.User = nil
	queried.Fragment = ""
	metadata.URL = queried.String()
	metadata.Host = strings.ToLower(strings.TrimSuffix(target.Hostname(), "."))

	var urlAnswer urlResponse
	if err := l.query("/v1/url/", url.Values{"url": {metadata.URL}}, &urlAnswer); err != nil {
		metadata.LookupError = "URL lookup failed: " + err.Error()
		return metadata
	}
	if urlAnswer.QueryStatus == queryStatusOK {
		entry := urlAnswer.URLhausEntry
		metadata.URLListed = true
		metadata.URLEntry = &entry
	}

	var hostAnswer hostResponse
	if err := l.query("/v1/host/", url.Values{"host": {metadata.Host}}, &hostAnswer); err != nil {
		metadata.LookupError = "host lookup failed: " + err.Error()
		return metadata
	}
	if hostAnswer.QueryStatus == queryStatusOK {
		metadata.HostListed = true
		metadata.HostReference = hostAnswer.Reference
		metadata.HostURLCount = max(int(hostAnswer.URLCount), len(hostAnswer.URLs))
		metadata.Blacklists = hostAnswer.Blacklists
		metadata.AbusedLegitimate = slices.Contains(l.AbusedLegitimate, hostAnswer.Blacklists.SpamhausDBL)
		metadata.MaliciousListing = slices.Contains(l.Malicious, hostAnswer.Blacklists.SpamhausDBL) ||
			hostAnswer.Blacklists.SURBL == surblListed

		// Online URLs first, so the reported sample shows what is live right now
		for _, entry := range hostAnswer.URLs {
			if entry.Status == urlStatusOnline {
				metadata.HostOnlineURLs++
			}
		}
		slices.SortStableFunc(hostAnswer.URLs, func(a, b URLhausEntry) int {
			return boolRank(b.Status == urlStatusOnline) - boolRank(a.Status == urlStatusOnline)
		})
		metadata.HostURLs = hostAnswer.URLs[:min(len(hostAnswer.URLs), l.MaxReportedURLs)]
	}

	metadata.Checked = true
	return metadata
}

// query posts a form to one URLhaus endpoint and decodes the answer, failing on anything
// other than a listed or an unlisted result.
func (l Lookup) query(endpoint string, form url.Values, answer any) error {
	request, err := http.NewRequest(http.MethodPost, l.BaseURL+endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Auth-Key", l.AuthKey)

	response, err := l.HTTPClient.Do(request)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := response.Body.Close(); cerr != nil {
			fmt.Printf("HttpClient \nWarning: Failed to close response channel: %s", cerr.Error())
		}
	}()

	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("URLhaus answered HTTP %d", response.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, l.MaxResponseSize))
	if err != nil {
		return err
	}
	if err := json.Unmarshal(body, answer); err != nil {
		return fmt.Errorf("unreadable URLhaus answer: %w", err)
	}

	var status struct {
		QueryStatus string `json:"query_status"`
	}
	_ = json.Unmarshal(body, &status)
	if status.QueryStatus != queryStatusOK && status.QueryStatus != queryStatusNoResults {
		return fmt.Errorf("URLhaus answered query_status %q", status.QueryStatus)
	}
	return nil
}

// boolRank orders true before false.
func boolRank(value bool) int {
	if value {
		return 1
	}
	return 0
}

// EvaluateThreat grades the lookup. The exact URL being listed outweighs anything known about
// its host, and a host that is a legitimate service somebody abused is barely a finding.
func EvaluateThreat(metadata URLhausMetadata) SiteTests.ThreatLevel {
	switch {
	case !metadata.Checked:
		return SiteTests.Info
	case metadata.URLListed && metadata.URLEntry.Status == urlStatusOnline:
		return SiteTests.Critical
	case metadata.URLListed:
		return SiteTests.High
	case !metadata.HostListed:
		return SiteTests.None
	case metadata.AbusedLegitimate && metadata.HostOnlineURLs > 0:
		return SiteTests.Low
	case metadata.AbusedLegitimate:
		return SiteTests.Info
	}

	level := SiteTests.Medium
	if metadata.HostOnlineURLs > 0 {
		level = SiteTests.High
	}
	if metadata.MaliciousListing {
		level = SiteTests.EscalateThreatLevel(level)
	}
	return level
}

// Describe creates a human-readable description of the lookup.
func Describe(metadata URLhausMetadata) string {
	if !metadata.Checked {
		return "URLhaus could not be consulted (" + metadata.LookupError + "), so the target was not checked against it."
	}

	if !metadata.URLListed && !metadata.HostListed {
		return fmt.Sprintf("Neither %s nor its host %s is listed in URLhaus. A single blocklist cannot prove a site safe, but no malware distribution has been reported here.",
			metadata.URL, metadata.Host)
	}

	description := ""
	if metadata.URLListed {
		entry := metadata.URLEntry
		description += fmt.Sprintf("The target URL is listed in URLhaus as %s, currently %s, reported on %s", entry.Threat, entry.Status, entry.DateAdded)
		if len(entry.Tags) > 0 {
			description += " with tags " + strings.Join(entry.Tags, ", ")
		}
		description += fmt.Sprintf(" (%s).\n", entry.Reference)
	}

	if metadata.HostListed {
		description += fmt.Sprintf("The host %s has %d URL(s) recorded in URLhaus, %d of the listed ones still online (%s).\n",
			metadata.Host, metadata.HostURLCount, metadata.HostOnlineURLs, metadata.HostReference)
		if metadata.AbusedLegitimate {
			description += fmt.Sprintf("Spamhaus classifies the domain as %s: a legitimate service that was abused to host them, which says little about the target itself.\n",
				metadata.Blacklists.SpamhausDBL)
		} else if metadata.MaliciousListing {
			description += fmt.Sprintf("The domain is also blocklisted (Spamhaus DBL: %s, SURBL: %s).\n",
				metadata.Blacklists.SpamhausDBL, metadata.Blacklists.SURBL)
		}
		for _, entry := range metadata.HostURLs {
			description += fmt.Sprintf("  - [%s] %s: %s\n", entry.Status, entry.Threat, entry.URL)
		}
		if hidden := metadata.HostURLCount - len(metadata.HostURLs); hidden > 0 {
			description += fmt.Sprintf("  ... and %d more\n", hidden)
		}
	}

	return description
}
