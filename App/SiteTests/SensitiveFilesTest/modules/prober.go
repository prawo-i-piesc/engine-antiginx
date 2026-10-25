// Package modules holds the stage implementations of the Sensitive File Exposure test.
// It is used by its own core.go and nothing else.
package modules

import (
	"Engine-AntiGinx/App/SSRF"
	"Engine-AntiGinx/App/SiteTests"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"sort"
	"sync"
	"time"
)

// Candidate is one file to request, carrying the category it is reported under. core.go
// builds the list from the shared SensitivePaths data, so this package owns no dataset.
type Candidate struct {
	Path     string
	Category string
}

// Prober requests candidate files and tells a real hit from a server that answers for
// everything.
type Prober struct {
	Timeout          time.Duration
	MaxBodyBytes     int64
	MaxConcurrency   int
	SoftMatchPercent int
}

// Exposure is one candidate the server did not treat as missing.
type Exposure struct {
	Path        string `json:"path"`
	URL         string `json:"url"`
	Category    string `json:"category"`
	Status      int    `json:"status"`
	Protected   bool   `json:"protected"` // true: exists but access-controlled (401/403); false: readable
	Size        int    `json:"size"`
	ContentType string `json:"content_type"`
}

// Analysis is everything the sweep established about the target.
type Analysis struct {
	Probed         int        `json:"probed"`
	SoftNotFound   bool       `json:"soft_not_found"` // the server returns 200 for missing paths
	BaselineStatus []int      `json:"baseline_status"`
	Exposures      []Exposure `json:"exposures"`
	ReadableCount  int        `json:"readable_count"`
	ProtectedCount int        `json:"protected_count"`
}

// baseline is what the server does with paths that certainly do not exist.
type baseline struct {
	statuses    map[int]bool
	soft200Size int // body length of a soft-404 200 page, when there is one
	soft200     bool
}

// Sweep probes every candidate and returns what was exposed.
func (p Prober) Sweep(baseUrl string, candidates []Candidate) Analysis {
	analysis := Analysis{Probed: len(candidates), Exposures: []Exposure{}}
	client := SSRF.NewClient(p.Timeout)

	base := p.baseline(client, baseUrl)
	analysis.SoftNotFound = base.soft200
	for status := range base.statuses {
		analysis.BaselineStatus = append(analysis.BaselineStatus, status)
	}
	sort.Ints(analysis.BaselineStatus)

	var mutex sync.Mutex
	var group sync.WaitGroup
	slots := make(chan struct{}, max(p.MaxConcurrency, 1))

	for _, candidate := range candidates {
		group.Add(1)
		slots <- struct{}{}
		go func(candidate Candidate) {
			defer group.Done()
			defer func() { <-slots }()

			exposure, found := p.probe(client, baseUrl, candidate, base)
			if !found {
				return
			}
			mutex.Lock()
			analysis.Exposures = append(analysis.Exposures, exposure)
			mutex.Unlock()
		}(candidate)
	}
	group.Wait()

	sort.Slice(analysis.Exposures, func(i, j int) bool { return analysis.Exposures[i].Path < analysis.Exposures[j].Path })
	for _, exposure := range analysis.Exposures {
		if exposure.Protected {
			analysis.ProtectedCount++
		} else {
			analysis.ReadableCount++
		}
	}
	return analysis
}

// baseline requests paths that cannot exist, so a server that answers 200 (or 403) for
// everything is not mistaken for one exposing files.
func (p Prober) baseline(client *http.Client, baseUrl string) baseline {
	base := baseline{statuses: map[int]bool{}}
	for _, probe := range []string{"/" + randomToken(), "/" + randomToken() + ".txt", "/" + randomToken() + ".bak"} {
		status, _, body, ok := p.fetch(client, baseUrl+probe)
		if !ok {
			continue
		}
		base.statuses[status] = true
		if status == http.StatusOK {
			base.soft200 = true
			base.soft200Size = len(body)
		}
	}
	return base
}

// probe requests one candidate and classifies the answer against the baseline.
func (p Prober) probe(client *http.Client, baseUrl string, candidate Candidate, base baseline) (Exposure, bool) {
	status, contentType, body, ok := p.fetch(client, baseUrl+candidate.Path)
	if !ok {
		return Exposure{}, false
	}

	exposure := Exposure{
		Path:        candidate.Path,
		URL:         baseUrl + candidate.Path,
		Category:    candidate.Category,
		Status:      status,
		Size:        len(body),
		ContentType: contentType,
	}

	switch {
	case status == http.StatusOK:
		// On a soft-404 server a 200 only counts when the body is clearly not the catch-all page.
		if base.soft200 && similarSize(len(body), base.soft200Size, p.SoftMatchPercent) {
			return Exposure{}, false
		}
		return exposure, true
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		// The file exists but is access-controlled — only a signal if the server does not
		// answer this way for everything.
		if base.statuses[status] {
			return Exposure{}, false
		}
		exposure.Protected = true
		return exposure, true
	default:
		return Exposure{}, false
	}
}

// fetch requests a URL and returns its status, its content type and the first MaxBodyBytes
// of its body.
func (p Prober) fetch(client *http.Client, target string) (int, string, string, bool) {
	// A body that failed to read still leaves a status worth classifying
	page, _ := SiteTests.Fetch(client, target, p.MaxBodyBytes)
	if page.Status == 0 {
		return 0, "", "", false
	}
	return page.Status, page.Header.Get("Content-Type"), string(page.Body), true
}

// similarSize reports whether two body lengths are within percent of each other, which is how
// a soft-404 page is recognised across its small per-request variations.
func similarSize(a, b, percent int) bool {
	if a == b {
		return true
	}
	larger := a
	if b > larger {
		larger = b
	}
	diff := a - b
	if diff < 0 {
		diff = -diff
	}
	return larger > 0 && diff*100 <= percent*larger
}

// randomToken is an unguessable path segment, so the baseline paths do not exist.
func randomToken() string {
	buffer := make([]byte, 12)
	if _, err := rand.Read(buffer); err != nil {
		return "a9f3c7e1d5b2a9f3c7e1d5b2"
	}
	return hex.EncodeToString(buffer)
}

// Grader turns an analysis into a threat level.
type Grader struct {
	SeverityFor     func(category string) SiteTests.ThreatLevel
	EscalationCount int
}

// EvaluateThreat reports the severity of the most dangerous readable file, raised a level
// when several files are readable. A file that only exists behind access control is a Low
// note on its own and does not drive the verdict.
func (g Grader) EvaluateThreat(analysis Analysis) SiteTests.ThreatLevel {
	if len(analysis.Exposures) == 0 {
		return SiteTests.None
	}

	levels := make([]SiteTests.ThreatLevel, 0, len(analysis.Exposures))
	for _, exposure := range analysis.Exposures {
		if exposure.Protected {
			levels = append(levels, SiteTests.Low)
			continue
		}
		levels = append(levels, g.SeverityFor(exposure.Category))
	}

	highest := SiteTests.HighestThreatLevel(levels...)
	if analysis.ReadableCount >= g.EscalationCount {
		highest = SiteTests.EscalateThreatLevel(highest)
	}
	return highest
}

// Describe creates a human-readable description of the analysis.
func Describe(analysis Analysis) string {
	if len(analysis.Exposures) == 0 {
		note := ""
		if analysis.SoftNotFound {
			note = " The server answers 200 for missing paths, so only files whose content differed from that page would have been reported."
		}
		return fmt.Sprintf("No sensitive file was exposed: none of the %d probed files was readable on the server.%s", analysis.Probed, note)
	}

	description := fmt.Sprintf("Sensitive files are reachable on the server: %d of %d probed files were readable", analysis.ReadableCount, analysis.Probed)
	if analysis.ProtectedCount > 0 {
		description += fmt.Sprintf(", and %d more exist but are access-controlled", analysis.ProtectedCount)
	}
	description += ".\n\n"

	for _, exposure := range analysis.Exposures {
		state := fmt.Sprintf("readable, %d bytes", exposure.Size)
		if exposure.Protected {
			state = fmt.Sprintf("exists, HTTP %d", exposure.Status)
		}
		description += fmt.Sprintf("• %s [%s] — %s\n", exposure.Path, exposure.Category, state)
	}

	return description
}
