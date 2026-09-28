package modules

import (
	"Engine-AntiGinx/App/SiteTests"
	"net"
	"net/url"
	"sort"
	"strings"
)

// Where a form sends what was typed into it, relative to the page.
const (
	DestinationSameHost     = "same-host"     // The page's own hostname
	DestinationSameSite     = "same-site"     // Another hostname under the page's registered domain
	DestinationScripted     = "scripted"      // A javascript: action, so a script decides where the data goes
	DestinationUnresolvable = "unresolvable"  // Not a URL the browser would submit to
	DestinationProcessor    = "processor"     // An identity provider or payment gateway
	DestinationForeign      = "foreign"       // An unrelated domain
	DestinationIPAddress    = "ip-address"    // A bare IP address rather than a name
	DestinationInsecure     = "insecure-http" // Plain http:, readable by anyone on the path
	DestinationMailto       = "mailto"        // Handed to the visitor's mail client as an e-mail
	DestinationCollector    = "collector"     // A service that collects data on someone else's behalf
)

// Kinds of data-collection service.
const (
	CollectorMessenger      = "messenger"       // A chat bot or webhook: data lands in someone's chat
	CollectorFormBackend    = "form-backend"    // A hosted form or spreadsheet endpoint
	CollectorRequestCatcher = "request-catcher" // A request inspector or a tunnel to someone's machine
)

// Collector is a service that receives submitted data on someone else's behalf.
type Collector struct {
	Name string
	Kind string
	Host string // Matches the host and its subdomains
	Path string // When set, must prefix the path
}

// Marker is the text that identifies the collector's endpoint inside a script.
func (c Collector) Marker() string {
	return c.Host + c.Path
}

// Submission is one place a form submits to.
type Submission struct {
	Via           string `json:"Via"` // "form" for the action, "button" for a formaction override
	Method        string `json:"Method"`
	Action        string `json:"Action"`
	URL           string `json:"URL,omitempty"`
	Host          string `json:"Host,omitempty"`
	Destination   string `json:"Destination"`
	Provider      string `json:"Provider,omitempty"`      // Collector or processor the host belongs to
	CollectorKind string `json:"CollectorKind,omitempty"` // Set for collectors only
}

// Classifier decides where a form submits against the datasets the test owns.
type Classifier struct {
	Collectors []Collector
	Processors map[string]string
}

// Classify resolves one form action against the document base and names its destination
// relative to the page. An empty action submits to the page's own address.
func (c Classifier) Classify(page *url.URL, base *url.URL, action string) Submission {
	submission := Submission{Action: action}
	lowered := strings.ToLower(action)

	switch {
	case strings.HasPrefix(lowered, "mailto:"):
		submission.Destination = DestinationMailto
		return submission
	case strings.HasPrefix(lowered, "javascript:"):
		submission.Destination = DestinationScripted
		return submission
	}

	target := page
	if action != "" {
		parsed, err := url.Parse(action)
		if err != nil {
			submission.Destination = DestinationUnresolvable
			return submission
		}
		target = base.ResolveReference(parsed)
	}
	if target.Scheme != "http" && target.Scheme != "https" || target.Hostname() == "" {
		submission.Destination = DestinationUnresolvable
		return submission
	}

	host := normalizeHost(target.Hostname())
	pageHost := normalizeHost(page.Hostname())
	submission.URL = target.String()
	submission.Host = host

	if collector, found := c.collectorOf(host, target.Path); found {
		submission.Destination = DestinationCollector
		submission.Provider = collector.Name
		submission.CollectorKind = collector.Kind
		return submission
	}

	switch {
	case target.Scheme == "http":
		submission.Destination = DestinationInsecure
	case host == pageHost:
		submission.Destination = DestinationSameHost
	case SiteTests.RegistrableDomain(host) == SiteTests.RegistrableDomain(pageHost):
		submission.Destination = DestinationSameSite
	case net.ParseIP(host) != nil:
		submission.Destination = DestinationIPAddress
	default:
		if processor := c.processorOf(host); processor != "" {
			submission.Destination = DestinationProcessor
			submission.Provider = processor
		} else {
			submission.Destination = DestinationForeign
		}
	}
	return submission
}

// collectorOf returns the data-collection service an endpoint belongs to, if any.
func (c Classifier) collectorOf(host string, path string) (Collector, bool) {
	path = strings.ToLower(path)
	for _, collector := range c.Collectors {
		if hostWithin(host, collector.Host) && strings.HasPrefix(path, collector.Path) {
			return collector, true
		}
	}
	return Collector{}, false
}

// processorOf returns the identity provider or payment gateway a hostname belongs to,
// preferring the most specific suffix.
func (c Classifier) processorOf(host string) string {
	suffixes := make([]string, 0, len(c.Processors))
	for suffix := range c.Processors {
		suffixes = append(suffixes, suffix)
	}
	sort.Slice(suffixes, func(first int, second int) bool {
		return len(suffixes[first]) > len(suffixes[second])
	})

	for _, suffix := range suffixes {
		if hostWithin(host, suffix) {
			return c.Processors[suffix]
		}
	}
	return ""
}

// hostWithin reports whether a hostname is a domain or one of its subdomains.
func hostWithin(host string, domain string) bool {
	return host == domain || strings.HasSuffix(host, "."+domain)
}

// normalizeHost lowercases a hostname and drops the trailing root dot.
func normalizeHost(host string) string {
	return strings.ToLower(strings.TrimSuffix(host, "."))
}
