// Package modules holds the stage implementations of the Directory Listing Detection test.
// It is used by its own core.go and nothing else.
package modules

import (
	"Engine-AntiGinx/App/SSRF"
	"Engine-AntiGinx/App/SiteTests"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Signature is a set of markers that together identify one server's generated listing.
type Signature struct {
	Server  string
	Markers []string
}

// Probe is one directory to request, and whether a listing there is graded as sensitive.
type Probe struct {
	Path      string
	Sensitive bool
}

// Scanner requests directories and recognises generated listings in the answers.
type Scanner struct {
	Signatures       []Signature
	Timeout          time.Duration
	MaxBodyBytes     int64
	MaxConcurrency   int
	MaxSampleEntries int
}

// DirectoryListing is one directory that answered with a generated listing.
type DirectoryListing struct {
	Path       string   `json:"path"`
	URL        string   `json:"url"`
	Server     string   `json:"server"`
	Sensitive  bool     `json:"sensitive"`
	EntryCount int      `json:"entry_count"`
	Entries    []string `json:"entries"`
}

// ListingAnalysis is everything the probes established about the target.
type ListingAnalysis struct {
	ProbedPaths     int                `json:"probed_paths"`
	ReachablePaths  int                `json:"reachable_paths"`
	Listings        []DirectoryListing `json:"listings"`
	TotalListings   int                `json:"total_listings"`
	SensitiveCount  int                `json:"sensitive_listings"`
	RootListingOpen bool               `json:"root_listing"`
}

// hrefPattern captures link targets, which is how every listing format names its entries.
var hrefPattern = regexp.MustCompile(`(?i)href\s*=\s*["']([^"']+)["']`)

// Scan probes every directory, at most MaxConcurrency at a time, and collects the listings.
func (s Scanner) Scan(baseUrl string, probes []Probe) ListingAnalysis {
	analysis := ListingAnalysis{ProbedPaths: len(probes), Listings: []DirectoryListing{}}
	client := SSRF.NewClient(s.Timeout)

	var mutex sync.Mutex
	var group sync.WaitGroup
	slots := make(chan struct{}, max(s.MaxConcurrency, 1))

	for _, probe := range probes {
		group.Add(1)
		slots <- struct{}{}
		go func(probe Probe) {
			defer group.Done()
			defer func() { <-slots }()

			body, reachable := s.fetch(client, baseUrl+probe.Path)
			if !reachable {
				return
			}
			server, isListing := s.Detect(body)

			mutex.Lock()
			defer mutex.Unlock()
			analysis.ReachablePaths++
			if !isListing {
				return
			}
			entries := ExtractEntries(body, probe.Path)
			analysis.Listings = append(analysis.Listings, DirectoryListing{
				Path:       probe.Path,
				URL:        baseUrl + probe.Path,
				Server:     server,
				Sensitive:  probe.Sensitive,
				EntryCount: len(entries),
				Entries:    entries[:min(len(entries), s.MaxSampleEntries)],
			})
		}(probe)
	}
	group.Wait()

	// Goroutines finish in any order; reports should not
	sort.Slice(analysis.Listings, func(i, j int) bool { return analysis.Listings[i].Path < analysis.Listings[j].Path })
	for _, listing := range analysis.Listings {
		if listing.Sensitive {
			analysis.SensitiveCount++
		}
		if listing.Path == "/" {
			analysis.RootListingOpen = true
		}
	}
	analysis.TotalListings = len(analysis.Listings)
	return analysis
}

// fetch requests one directory and returns its body when it answered 200 with a document a
// listing could be in.
func (s Scanner) fetch(client *http.Client, target string) (string, bool) {
	resp, err := client.Get(target)
	if err != nil {
		return "", false
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			fmt.Printf("HttpClient \nWarning: Failed to close response channel: %s", cerr.Error())
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return "", false
	}
	contentType := strings.ToLower(resp.Header.Get("Content-Type"))
	if contentType != "" && !strings.Contains(contentType, "html") && !strings.HasPrefix(contentType, "text/") {
		return "", false
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, s.MaxBodyBytes))
	if err != nil {
		return "", false
	}
	return string(body), true
}

// Detect returns the server whose listing signature the body matches, if any.
func (s Scanner) Detect(body string) (string, bool) {
	lowered := strings.ToLower(body)
	for _, signature := range s.Signatures {
		if len(signature.Markers) == 0 {
			continue
		}
		matched := true
		for _, marker := range signature.Markers {
			if !strings.Contains(lowered, marker) {
				matched = false
				break
			}
		}
		if matched {
			return signature.Server, true
		}
	}
	return "", false
}

// ExtractEntries returns the files and directories a listing links to, leaving out the parent
// directory, the column-sorting links and anything pointing outside the listed directory.
func ExtractEntries(body string, directory string) []string {
	entries := []string{}
	seen := map[string]bool{}

	for _, match := range hrefPattern.FindAllStringSubmatch(body, -1) {
		href := strings.TrimSpace(match[1])
		lowered := strings.ToLower(href)

		switch {
		case href == "" || href == "/" || href == "./" || strings.HasPrefix(href, "../"),
			strings.HasPrefix(href, "?"), strings.HasPrefix(href, "#"),
			strings.Contains(lowered, "://"), strings.HasPrefix(lowered, "mailto:"),
			strings.HasPrefix(lowered, "javascript:"):
			continue
		}

		// Absolute links (IIS, some autoindex modules) must stay inside the listed directory
		if strings.HasPrefix(href, "/") {
			if !strings.HasPrefix(href, directory) || href == directory {
				continue
			}
			href = strings.TrimPrefix(href, directory)
		}

		if !seen[href] {
			seen[href] = true
			entries = append(entries, href)
		}
	}
	return entries
}

// EvaluateThreat grades a listing of the web root or of a sensitive directory as High and any
// other listing as Medium, as OWASP ZAP rates Directory Browsing. Each listing is rated on its
// own, so how many directories are listed never raises the level.
func EvaluateThreat(analysis ListingAnalysis) SiteTests.ThreatLevel {
	switch {
	case analysis.TotalListings == 0:
		return SiteTests.None
	case analysis.RootListingOpen || analysis.SensitiveCount > 0:
		return SiteTests.High
	default:
		return SiteTests.Medium
	}
}

// Describe creates a human-readable description of the analysis.
func Describe(analysis ListingAnalysis) string {
	if analysis.TotalListings == 0 {
		return fmt.Sprintf("No directory listing found: none of the %d probed directories (%d reachable) answered with a server-generated index.",
			analysis.ProbedPaths, analysis.ReachablePaths)
	}

	description := fmt.Sprintf("Directory listing is enabled: %d of %d probed directories answer with a server-generated index of their files",
		analysis.TotalListings, analysis.ProbedPaths)
	if analysis.SensitiveCount > 0 {
		description += fmt.Sprintf(", %d of them in directories that typically hold uploads, backups, logs or code", analysis.SensitiveCount)
	}
	description += ". Anyone can browse and download every file in them, including ones never linked from the site.\n\n"

	for _, listing := range analysis.Listings {
		marker := ""
		if listing.Sensitive {
			marker = " [sensitive]"
		}
		description += fmt.Sprintf("• %s%s (%s, %d entries)\n", listing.Path, marker, listing.Server, listing.EntryCount)
		for _, entry := range listing.Entries[:min(len(listing.Entries), 3)] {
			description += fmt.Sprintf("  - %s\n", entry)
		}
		if listing.EntryCount > 3 {
			description += fmt.Sprintf("  ... and %d more\n", listing.EntryCount-3)
		}
	}

	return description
}
