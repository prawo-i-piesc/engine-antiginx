package modules

import (
	"Engine-AntiGinx/App/SiteTests"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// maxRDAPResponseSize caps how much of an RDAP response is read.
const maxRDAPResponseSize = 1 << 20

// UnknownDayCount is what a day counter holds when the date it derives from was not published,
// which registries increasingly do for privacy reasons.
const UnknownDayCount = -1

// DNSIndicator is one phishing relevant observation derived from the collected evidence.
type DNSIndicator struct {
	Code     string                `json:"Code"`
	Detail   string                `json:"Detail"`
	Severity SiteTests.ThreatLevel `json:"Severity"`
}

// DNSReputationMetadata is the complete evidence set behind the DNS reputation verdict.
type DNSReputationMetadata struct {
	Host               string                 `json:"Host"`
	RegistrableDomain  string                 `json:"RegistrableDomain"`
	Registration       DomainRegistrationInfo `json:"Registration"`
	Resolution         DomainResolutionInfo   `json:"Resolution"`
	MailAuthentication MailAuthenticationInfo `json:"MailAuthentication"`
	Networks           []AddressNetworkInfo   `json:"Networks"`
	Indicators         []DNSIndicator         `json:"Indicators"`
}

// DomainRegistrationInfo holds the registration record of the analysed domain.
type DomainRegistrationInfo struct {
	Resolved               bool       `json:"Resolved"`
	Source                 string     `json:"Source"`
	LookupError            string     `json:"LookupError"`
	Domain                 string     `json:"Domain"`
	TLD                    string     `json:"TLD"`
	Registrar              string     `json:"Registrar"`
	RegistrarCountry       string     `json:"RegistrarCountry"`
	RegistrarIANAId        string     `json:"RegistrarIANAId"`
	RegistrantCountry      string     `json:"RegistrantCountry"`
	Registered             *time.Time `json:"Registered"`
	Expires                *time.Time `json:"Expires"`
	LastChanged            *time.Time `json:"LastChanged"`
	Transferred            *time.Time `json:"Transferred"`
	AgeDays                int        `json:"AgeDays"`
	TenureDays             int        `json:"TenureDays"`
	LastChangedDaysAgo     int        `json:"LastChangedDaysAgo"`
	DaysUntilExpiry        int        `json:"DaysUntilExpiry"`
	RegistrationPeriodDays int        `json:"RegistrationPeriodDays"`
	Statuses               []string   `json:"Statuses"`
	Nameservers            []string   `json:"Nameservers"`
	DNSSECSigned           bool       `json:"DNSSECSigned"`
}

// DomainResolutionInfo holds what the DNS says about the analysed hostname.
type DomainResolutionInfo struct {
	Resolved            bool     `json:"Resolved"`
	LookupError         string   `json:"LookupError"`
	IPv4Addresses       []string `json:"IPv4Addresses"`
	IPv6Addresses       []string `json:"IPv6Addresses"`
	CanonicalName       string   `json:"CanonicalName"`
	AliasedToService    string   `json:"AliasedToService"`
	Nameservers         []string `json:"Nameservers"`
	NameserverProviders []string `json:"NameserverProviders"`
	MailExchangers      []string `json:"MailExchangers"`
	WildcardDNS         bool     `json:"WildcardDNS"`
	HostingService      string   `json:"HostingService"`
	HostingServiceKind  string   `json:"HostingServiceKind"`
}

// MailAuthenticationInfo holds the mail policy published in the domain's zone.
type MailAuthenticationInfo struct {
	SPFRecord             string `json:"SPFRecord"`
	SPFPresent            bool   `json:"SPFPresent"`
	SPFAllowsAnySender    bool   `json:"SPFAllowsAnySender"`
	DMARCRecord           string `json:"DMARCRecord"`
	DMARCPresent          bool   `json:"DMARCPresent"`
	DMARCPolicy           string `json:"DMARCPolicy"`
	MailExchangersPresent bool   `json:"MailExchangersPresent"`
}

// AddressNetworkInfo describes one resolved address and the network it belongs to.
type AddressNetworkInfo struct {
	Address            string   `json:"Address"`
	Public             bool     `json:"Public"`
	Scope              string   `json:"Scope"`
	Network            string   `json:"Network"`
	Organization       string   `json:"Organization"`
	Country            string   `json:"Country"`
	AllocationType     string   `json:"AllocationType"`
	AbusePublished     bool     `json:"AbusePublished"`
	ReverseNames       []string `json:"ReverseNames"`
	DynamicReverseName bool     `json:"DynamicReverseName"`
	LookupError        string   `json:"LookupError"`
}

// errRDAPNotFound reports that the RDAP service answered but holds no record for the queried
// object.
var errRDAPNotFound = errors.New("rdap: object not found")

// dnsReputationCollector gathers the evidence the DNS reputation test reasons about.
type Collector struct {
	Resolver     *net.Resolver
	HTTPClient   *http.Client
	RDAPBaseURL  string
	RDAPTimeout  time.Duration
	DNSTimeout   time.Duration
	MaxAddresses int
	Names        Names
	Now          func() time.Time
}

// Collect gathers every piece of evidence about a hostname and returns it as the metadata the
// verdict is derived from.
func (c *Collector) Collect(host string) DNSReputationMetadata {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	domain := c.Names.RegistrableDomain(host)
	service, serviceKind := c.Names.MatchManagedService(host)

	var registration DomainRegistrationInfo
	var resolution DomainResolutionInfo
	var mail MailAuthenticationInfo

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		registration = c.lookupRegistration(registrationCandidates(host, domain))
	}()
	go func() {
		defer wg.Done()
		resolution, mail = c.lookupZone(host, domain)
	}()
	wg.Wait()

	resolution.HostingService = service
	resolution.HostingServiceKind = serviceKind
	if resolution.CanonicalName != "" {
		if aliasService, _ := c.Names.MatchManagedService(resolution.CanonicalName); aliasService != "" && aliasService != service {
			resolution.AliasedToService = aliasService
		}
	}
	resolution.NameserverProviders = c.Names.MatchFreeDNSProviders(resolution.Nameservers)

	return DNSReputationMetadata{
		Host:               host,
		RegistrableDomain:  domain,
		Registration:       registration,
		Resolution:         resolution,
		MailAuthentication: mail,
		Networks:           c.inspectAddresses(resolution),
		Indicators:         []DNSIndicator{},
	}
}

// lookupRegistration retrieves the registration record of the first candidate the RDAP service
// knows about.
func (c *Collector) lookupRegistration(candidates []string) DomainRegistrationInfo {
	info := emptyRegistrationInfo()

	var lastErr error
	for _, candidate := range candidates {
		record := rdapDomainRecord{}
		err := c.fetchRDAP("/domain/"+url.PathEscape(candidate), &record)
		if err == nil {
			return c.buildRegistrationInfo(candidate, record)
		}

		lastErr = err
		if !errors.Is(err, errRDAPNotFound) {
			break
		}
	}

	if lastErr != nil {
		info.LookupError = lastErr.Error()
	}
	if len(candidates) > 0 {
		info.Domain = candidates[0]
		info.TLD = topLevelDomain(candidates[0])
	}
	return info
}

// emptyRegistrationInfo returns a registration record with every day counter marked unknown,
// so an unresolved lookup can never be read as "registered today".
func emptyRegistrationInfo() DomainRegistrationInfo {
	return DomainRegistrationInfo{
		AgeDays:                UnknownDayCount,
		TenureDays:             UnknownDayCount,
		LastChangedDaysAgo:     UnknownDayCount,
		DaysUntilExpiry:        UnknownDayCount,
		RegistrationPeriodDays: UnknownDayCount,
		Statuses:               []string{},
		Nameservers:            []string{},
	}
}

// buildRegistrationInfo converts an RDAP record into the registration section of the metadata
// and derives the day counters the verdict reasons about.
func (c *Collector) buildRegistrationInfo(domain string, record rdapDomainRecord) DomainRegistrationInfo {
	info := emptyRegistrationInfo()
	info.Resolved = true
	info.Source = "RDAP"
	info.Domain = domain
	if record.LdhName != "" {
		info.Domain = strings.ToLower(strings.TrimSuffix(record.LdhName, "."))
	}
	info.TLD = topLevelDomain(info.Domain)
	info.Statuses = normalizeStatuses(record.Status)
	info.Nameservers = record.nameserverNames()
	info.DNSSECSigned = record.SecureDNS != nil && record.SecureDNS.DelegationSigned

	registrar := record.entityByRole("registrar")
	if registrar != nil {
		card := parseVCard(registrar.VCardArray)
		info.Registrar = card.organization()
		info.RegistrarCountry = card.Country
		info.RegistrarIANAId = registrar.publicID("IANA Registrar ID")
	}
	if registrant := record.entityByRole("registrant"); registrant != nil {
		info.RegistrantCountry = parseVCard(registrant.VCardArray).Country
	}

	info.Registered = record.eventDate("registration")
	info.Expires = record.eventDate("expiration")
	info.LastChanged = record.eventDate("last changed")
	info.Transferred = record.eventDate("transfer")

	deriveRegistrationTiming(&info, c.Now())
	return info
}

// deriveRegistrationTiming fills in the day counters from the dates in the record.
func deriveRegistrationTiming(info *DomainRegistrationInfo, now time.Time) {
	if info.Registered != nil {
		info.AgeDays = daysBetween(*info.Registered, now)
		info.TenureDays = info.AgeDays
	}
	if info.Transferred != nil {
		info.TenureDays = daysBetween(*info.Transferred, now)
	}
	if info.LastChanged != nil {
		info.LastChangedDaysAgo = daysBetween(*info.LastChanged, now)
	}
	if info.Expires != nil {
		info.DaysUntilExpiry = daysBetween(now, *info.Expires)
		if info.Registered != nil {
			info.RegistrationPeriodDays = daysBetween(*info.Registered, *info.Expires)
		}
	}
}

// daysBetween returns the number of whole days from one instant to another.
func daysBetween(from time.Time, to time.Time) int {
	return int(to.Sub(from).Hours() / 24)
}

// lookupZone queries everything the DNS can say about the hostname and its zone in one batch,
// and splits the answers into the resolution and mail policy sections.
func (c *Collector) lookupZone(host string, domain string) (DomainResolutionInfo, MailAuthenticationInfo) {
	ctx, cancel := context.WithTimeout(context.Background(), c.DNSTimeout)
	defer cancel()

	var (
		addresses   []net.IPAddr
		addressErr  error
		canonical   string
		nameservers []*net.NS
		exchangers  []*net.MX
		zoneRecords []string
		dmarcRecord []string
		wildcard    bool
	)

	var wg sync.WaitGroup
	wg.Add(7)
	go func() {
		defer wg.Done()
		addresses, addressErr = c.Resolver.LookupIPAddr(ctx, host)
	}()
	go func() {
		defer wg.Done()
		canonical, _ = c.Resolver.LookupCNAME(ctx, host)
	}()
	go func() {
		defer wg.Done()
		nameservers, _ = c.Resolver.LookupNS(ctx, domain)
	}()
	go func() {
		defer wg.Done()
		exchangers, _ = c.Resolver.LookupMX(ctx, domain)
	}()
	go func() {
		defer wg.Done()
		zoneRecords, _ = c.Resolver.LookupTXT(ctx, domain)
	}()
	go func() {
		defer wg.Done()
		dmarcRecord, _ = c.Resolver.LookupTXT(ctx, "_dmarc."+domain)
	}()
	go func() {
		defer wg.Done()
		wildcard = c.probeWildcard(ctx, domain)
	}()
	wg.Wait()

	resolution := DomainResolutionInfo{
		IPv4Addresses:       []string{},
		IPv6Addresses:       []string{},
		Nameservers:         []string{},
		NameserverProviders: []string{},
		MailExchangers:      []string{},
	}
	if addressErr != nil {
		resolution.LookupError = addressErr.Error()
	}
	for _, address := range addresses {
		if v4 := address.IP.To4(); v4 != nil {
			resolution.IPv4Addresses = append(resolution.IPv4Addresses, v4.String())
			continue
		}
		resolution.IPv6Addresses = append(resolution.IPv6Addresses, address.IP.String())
	}
	resolution.Resolved = len(addresses) > 0
	sort.Strings(resolution.IPv4Addresses)
	sort.Strings(resolution.IPv6Addresses)

	if canonical = strings.ToLower(strings.TrimSuffix(canonical, ".")); canonical != "" && canonical != host {
		resolution.CanonicalName = canonical
	}
	for _, nameserver := range nameservers {
		resolution.Nameservers = append(resolution.Nameservers, strings.ToLower(strings.TrimSuffix(nameserver.Host, ".")))
	}
	sort.Strings(resolution.Nameservers)
	for _, exchanger := range exchangers {
		// A null MX is the single dot, and is kept as such: it is a deliberate statement
		// that the domain accepts no mail, which is evidence of a configured domain
		// rather than of an unconfigured one.
		name := strings.ToLower(strings.TrimSpace(exchanger.Host))
		if name != "." {
			name = strings.TrimSuffix(name, ".")
		}
		if name == "" {
			continue
		}
		resolution.MailExchangers = append(resolution.MailExchangers, name)
	}
	sort.Strings(resolution.MailExchangers)
	resolution.WildcardDNS = wildcard

	mail := MailAuthenticationInfo{MailExchangersPresent: len(resolution.MailExchangers) > 0}
	mail.SPFRecord = findSPFRecord(zoneRecords)
	mail.SPFPresent = mail.SPFRecord != ""
	mail.SPFAllowsAnySender = spfAllowsAnySender(mail.SPFRecord)
	mail.DMARCRecord = findDMARCRecord(dmarcRecord)
	mail.DMARCPresent = mail.DMARCRecord != ""
	mail.DMARCPolicy = dmarcPolicy(mail.DMARCRecord)

	return resolution, mail
}

// probeWildcard reports whether the zone answers for a name nobody ever configured. It shares
// the deadline of the batch it is issued with, because it depends on none of the other answers
// and so has no reason to cost the scan a second timeout of its own.
func (c *Collector) probeWildcard(ctx context.Context, domain string) bool {
	if domain == "" {
		return false
	}

	label := fmt.Sprintf("antiginx-probe-%d", rand.Int63())
	addresses, err := c.Resolver.LookupHost(ctx, label+"."+domain)
	return err == nil && len(addresses) > 0
}

// inspectAddresses gathers the network allocation and reverse names of the resolved addresses.
func (c *Collector) inspectAddresses(resolution DomainResolutionInfo) []AddressNetworkInfo {
	addresses := append(append([]string{}, resolution.IPv4Addresses...), resolution.IPv6Addresses...)
	if len(addresses) > c.MaxAddresses {
		addresses = addresses[:c.MaxAddresses]
	}

	networks := make([]AddressNetworkInfo, len(addresses))
	var wg sync.WaitGroup
	for index, address := range addresses {
		wg.Add(1)
		go func(index int, address string) {
			defer wg.Done()
			networks[index] = c.inspectAddress(address)
		}(index, address)
	}
	wg.Wait()
	return networks
}

// inspectAddress collects everything known about a single address: who it is allocated to and
// what it calls itself.
func (c *Collector) inspectAddress(address string) AddressNetworkInfo {
	info := AddressNetworkInfo{
		Address:      address,
		ReverseNames: []string{},
	}

	parsed := net.ParseIP(address)
	if parsed == nil {
		info.LookupError = "address could not be parsed"
		return info
	}

	scope := c.Names.AddressScope(parsed)
	info.Public = scope == ""
	info.Scope = scope
	if !info.Public {
		return info
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		record := rdapIPRecord{}
		if err := c.fetchRDAP("/ip/"+url.PathEscape(address), &record); err != nil {
			info.LookupError = err.Error()
			return
		}
		info.Network = record.networkName()
		info.Organization = record.organization()
		info.Country = strings.ToUpper(record.Country)
		if info.Country == "" {
			info.Country = strings.ToUpper(record.entityCountry())
		}
		info.AllocationType = record.Type
		info.AbusePublished = record.entityByRole("abuse") != nil
	}()

	go func() {
		defer wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), c.DNSTimeout)
		defer cancel()
		names, err := c.Resolver.LookupAddr(ctx, address)
		if err != nil {
			return
		}
		for _, name := range names {
			info.ReverseNames = append(info.ReverseNames, strings.ToLower(strings.TrimSuffix(name, ".")))
		}
		sort.Strings(info.ReverseNames)
		info.DynamicReverseName = c.Names.HasDynamicReverseName(info.ReverseNames)
	}()

	wg.Wait()
	return info
}

// fetchRDAP performs one RDAP request and decodes the response into the given value.
func (c *Collector) fetchRDAP(path string, out any) error {
	ctx, cancel := context.WithTimeout(context.Background(), c.RDAPTimeout)
	defer cancel()

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.RDAPBaseURL+path, nil)
	if err != nil {
		return fmt.Errorf("registration lookup could not be built: %w", err)
	}
	request.Header.Set("Accept", "application/rdap+json, application/json")
	request.Header.Set("User-Agent", "AntiGinx/1.0")

	response, err := c.HTTPClient.Do(request)
	if err != nil {
		return fmt.Errorf("registration lookup failed: %w", err)
	}
	defer func() {
		if cerr := response.Body.Close(); cerr != nil {
			fmt.Printf("DNSReputationTest \nWarning: Failed to close response body: %s", cerr.Error())
		}
	}()

	if response.StatusCode == http.StatusNotFound {
		return errRDAPNotFound
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("registration service answered with status %d", response.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, maxRDAPResponseSize))
	if err != nil {
		return fmt.Errorf("registration record could not be read: %w", err)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("registration record could not be decoded: %w", err)
	}
	return nil
}

// --------------------------------------------------------------------------
// RDAP wire format decoding
// --------------------------------------------------------------------------
//
// This file decodes the RDAP wire format into the handful of facts the DNS reputation
// test needs. RDAP is the protocol that replaced WHOIS for registration data, and its
// responses are deliberately generic: the same document shape describes a domain, an
// address block or a contact, and the interesting values are buried in role tagged
// entities and in jCard arrays, a JSON encoding of the vCard format.
//
// Only the fields the verdict uses are decoded, and every accessor tolerates a missing
// or differently shaped value, because registries vary widely in what they publish and
// how. A registry that omits half the record produces a partial report, never an error.
