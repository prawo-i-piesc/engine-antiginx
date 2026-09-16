package modules

import (
	"Engine-AntiGinx/App/SiteTests"
	"net"
	"net/url"
	"sort"
	"strings"
)

// Where an icon is loaded from, relative to the page declaring it.
const (
	OriginSameHost         = "same-host"         // The page's own hostname
	OriginSameSite         = "same-site"         // Another hostname under the page's registered domain
	OriginInline           = "inline"            // Embedded in the page as a data: URI
	OriginSameOrganisation = "same-organisation" // Another domain of the brand that runs the page
	OriginAssetHost        = "asset-host"        // A CDN or site platform serving it for the page's owner
	OriginForeign          = "foreign"           // An unrelated domain
	OriginIPAddress        = "ip-address"        // A bare IP address rather than a name
	OriginBrand            = "brand"             // A brand's domain, on a page the brand does not run
	OriginUnresolvable     = "unresolvable"      // Not a URL a browser would fetch an icon from
)

// IconReference is one declared icon and where it is loaded from.
type IconReference struct {
	Rel      string `json:"Rel"`
	Href     string `json:"Href"`
	URL      string `json:"URL,omitempty"`
	Host     string `json:"Host,omitempty"`
	Origin   string `json:"Origin"`
	Provider string `json:"Provider,omitempty"` // Brand or platform the host belongs to
}

// Classifier decides where an icon is loaded from against the datasets the test owns.
type Classifier struct {
	BrandDomains map[string][]string
	AssetHosts   map[string]string
}

// Classify resolves one icon declaration against the document base and names its origin
// relative to the page.
func (c Classifier) Classify(page *url.URL, base *url.URL, declaration IconDeclaration) IconReference {
	reference := IconReference{Rel: declaration.Rel, Href: declaration.Href}

	if strings.HasPrefix(strings.ToLower(declaration.Href), "data:") {
		reference.Origin = OriginInline
		return reference
	}

	parsed, err := url.Parse(declaration.Href)
	if err != nil {
		reference.Origin = OriginUnresolvable
		return reference
	}
	resolved := base.ResolveReference(parsed)
	if resolved.Scheme != "http" && resolved.Scheme != "https" || resolved.Hostname() == "" {
		reference.Origin = OriginUnresolvable
		return reference
	}

	iconHost := normalizeHost(resolved.Hostname())
	pageHost := normalizeHost(page.Hostname())
	reference.URL = resolved.String()
	reference.Host = iconHost

	switch {
	case iconHost == pageHost:
		reference.Origin = OriginSameHost
	case SiteTests.RegistrableDomain(iconHost) == SiteTests.RegistrableDomain(pageHost):
		reference.Origin = OriginSameSite
	case net.ParseIP(iconHost) != nil:
		reference.Origin = OriginIPAddress
	default:
		c.classifyForeignHost(&reference, iconHost, pageHost)
	}
	return reference
}

// classifyForeignHost names the origin of an icon served from a domain other than the page's.
func (c Classifier) classifyForeignHost(reference *IconReference, iconHost string, pageHost string) {
	if provider := c.assetProvider(iconHost); provider != "" {
		reference.Origin = OriginAssetHost
		reference.Provider = provider
		return
	}

	brand := c.brandOf(iconHost)
	switch {
	case brand == "":
		reference.Origin = OriginForeign
	case brand == c.brandOf(pageHost):
		reference.Origin = OriginSameOrganisation
		reference.Provider = brand
	default:
		reference.Origin = OriginBrand
		reference.Provider = brand
	}
}

// assetProvider returns the CDN or platform a hostname belongs to, preferring the most
// specific suffix so a CDN hosted under a brand's domain is recognised as the CDN.
func (c Classifier) assetProvider(host string) string {
	suffixes := make([]string, 0, len(c.AssetHosts))
	for suffix := range c.AssetHosts {
		suffixes = append(suffixes, suffix)
	}
	sort.Slice(suffixes, func(first int, second int) bool {
		return len(suffixes[first]) > len(suffixes[second])
	})

	for _, suffix := range suffixes {
		if hostWithin(host, suffix) {
			return c.AssetHosts[suffix]
		}
	}
	return ""
}

// brandOf returns the brand whose domains a hostname belongs to, if any.
func (c Classifier) brandOf(host string) string {
	for brand, domains := range c.BrandDomains {
		for _, domain := range domains {
			if hostWithin(host, domain) {
				return brand
			}
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
