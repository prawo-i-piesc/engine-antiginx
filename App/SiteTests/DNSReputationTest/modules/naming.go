package modules

import (
	"net"
	"strings"
)

// reservedRange is one non routable address range and the reason it is not routable.
type ReservedRange struct {
	Network *net.IPNet
	Scope   string
}

// Names classifies hostnames, nameservers and addresses against the datasets the test owns.
type Names struct {
	PublicSuffixes   map[string]bool
	ManagedServices  map[string]string
	FreeDNSProviders []string
	DynamicMarkers   []string
	ReservedRanges   []ReservedRange
}

// RegistrableDomain reduces a hostname to the domain somebody registered, which is the name
// registration data and zone level records are published for.
func (n Names) RegistrableDomain(host string) string {
	host = strings.ToLower(strings.Trim(strings.TrimSpace(host), "."))
	if host == "" || net.ParseIP(host) != nil {
		return host
	}

	labels := strings.Split(host, ".")
	if len(labels) < 3 {
		return host
	}

	lastTwo := strings.Join(labels[len(labels)-2:], ".")
	if n.PublicSuffixes[lastTwo] {
		return strings.Join(labels[len(labels)-3:], ".")
	}
	return lastTwo
}

// registrationCandidates lists the domains to try a registration lookup for, shortest first.
func registrationCandidates(host string, domain string) []string {
	if domain == "" {
		return []string{}
	}

	candidates := []string{domain}
	hostLabels := strings.Split(host, ".")
	domainLabels := strings.Split(domain, ".")
	if len(hostLabels) > len(domainLabels) {
		candidates = append(candidates, strings.Join(hostLabels[len(hostLabels)-len(domainLabels)-1:], "."))
	}
	return candidates
}

// topLevelDomain returns the last label of a domain.
func topLevelDomain(domain string) string {
	labels := strings.Split(strings.Trim(strings.TrimSpace(domain), "."), ".")
	if len(labels) == 0 {
		return ""
	}
	return strings.ToLower(labels[len(labels)-1])
}

// MatchManagedService reports which managed platform a hostname belongs to, if any.
func (n Names) MatchManagedService(host string) (string, string) {
	host = strings.ToLower(strings.Trim(strings.TrimSpace(host), "."))
	if host == "" {
		return "", ""
	}

	bestSuffix := ""
	bestKind := ""
	for suffix, kind := range n.ManagedServices {
		if host != suffix && !strings.HasSuffix(host, "."+suffix) {
			continue
		}
		if len(suffix) > len(bestSuffix) {
			bestSuffix = suffix
			bestKind = kind
		}
	}
	return bestSuffix, bestKind
}

// MatchFreeDNSProviders reports which of the nameservers serving a zone belong to providers
// that hand out zone hosting for free and without verification.
func (n Names) MatchFreeDNSProviders(nameservers []string) []string {
	providers := []string{}
	seen := map[string]bool{}

	for _, nameserver := range nameservers {
		name := strings.ToLower(strings.Trim(strings.TrimSpace(nameserver), "."))
		for _, provider := range n.FreeDNSProviders {
			if name != provider && !strings.HasSuffix(name, "."+provider) {
				continue
			}
			if seen[provider] {
				continue
			}
			seen[provider] = true
			providers = append(providers, provider)
		}
	}
	return providers
}

// HasDynamicReverseName reports whether any reverse name of an address follows the naming
// convention access providers use for their dynamically assigned pools.
func (n Names) HasDynamicReverseName(names []string) bool {
	for _, name := range names {
		lowered := strings.ToLower(name)
		for _, marker := range n.DynamicMarkers {
			if strings.Contains(lowered, marker) {
				return true
			}
		}
	}
	return false
}

// AddressScope reports why an address is not globally routable, and reports nothing for an
// address that is.
func (n Names) AddressScope(ip net.IP) string {
	switch {
	case ip == nil:
		return "unparsable address"
	case ip.IsUnspecified():
		return "unspecified address"
	case ip.IsLoopback():
		return "loopback address"
	case ip.IsPrivate():
		return "private network range"
	case ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast():
		return "link-local range"
	case ip.IsMulticast():
		return "multicast range"
	}

	for _, reserved := range n.ReservedRanges {
		if reserved.Network.Contains(ip) {
			return reserved.Scope
		}
	}
	return ""
}

// findSPFRecord returns the SPF policy published among a zone's TXT records.
func findSPFRecord(records []string) string {
	for _, record := range records {
		trimmed := strings.TrimSpace(record)
		if strings.HasPrefix(strings.ToLower(trimmed), "v=spf1") {
			return trimmed
		}
	}
	return ""
}

// spfAllowsAnySender reports whether an SPF record ends in a catch all that authorises every
// sender, which leaves the domain as spoofable as having no record at all while looking
// configured.
func spfAllowsAnySender(record string) bool {
	fields := strings.Fields(strings.ToLower(record))
	for _, field := range fields {
		if field == "all" || field == "+all" {
			return true
		}
	}
	return false
}

// findDMARCRecord returns the DMARC policy published at the zone's _dmarc name.
func findDMARCRecord(records []string) string {
	for _, record := range records {
		trimmed := strings.TrimSpace(record)
		if strings.HasPrefix(strings.ToLower(trimmed), "v=dmarc1") {
			return trimmed
		}
	}
	return ""
}

// dmarcPolicy returns the enforcement policy a DMARC record declares.
func dmarcPolicy(record string) string {
	for _, tag := range strings.Split(record, ";") {
		trimmed := strings.TrimSpace(strings.ToLower(tag))
		if strings.HasPrefix(trimmed, "p=") {
			return strings.TrimSpace(strings.TrimPrefix(trimmed, "p="))
		}
	}
	return ""
}
