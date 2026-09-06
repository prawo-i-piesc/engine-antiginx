package DNSReputationTest

import (
	"Engine-AntiGinx/App/SiteTests/DNSReputationTest/modules"
	"net"
)

// Categories of managed platform a hostname can belong to.
const (
	serviceKindTunnel      = "tunnel"       // Hostname handed out by a tunnelling service
	serviceKindFreeHosting = "free-hosting" // Hostname on a free or self service hosting platform
	serviceKindDynamicDNS  = "dynamic-dns"  // Hostname handed out by a dynamic DNS provider
)

// multiLabelPublicSuffixes are the public suffixes made of more than one label that the engine
// recognises locally, so that a hostname under one of them is reduced to the domain somebody
// actually registered rather than to the suffix itself.
var multiLabelPublicSuffixes = map[string]bool{
	"co.uk": true, "org.uk": true, "ac.uk": true, "gov.uk": true, "me.uk": true, "net.uk": true, "sch.uk": true,
	"com.pl": true, "net.pl": true, "org.pl": true, "edu.pl": true, "gov.pl": true, "info.pl": true, "waw.pl": true, "com.au": true,
	"net.au": true, "org.au": true, "edu.au": true, "gov.au": true, "id.au": true,
	"com.br": true, "net.br": true, "org.br": true, "gov.br": true,
	"com.cn": true, "net.cn": true, "org.cn": true, "gov.cn": true, "edu.cn": true,
	"co.jp": true, "or.jp": true, "ne.jp": true, "ac.jp": true, "go.jp": true,
	"co.kr": true, "or.kr": true, "co.in": true, "net.in": true, "org.in": true, "gov.in": true,
	"co.za": true, "org.za": true, "co.nz": true, "net.nz": true, "org.nz": true, "govt.nz": true,
	"com.mx": true, "com.ar": true, "com.co": true, "com.tr": true, "gov.tr": true, "com.ua": true,
	"com.sg": true, "com.hk": true, "com.tw": true, "com.my": true, "com.ph": true, "com.vn": true,
	"co.il": true, "co.id": true, "com.sa": true, "com.eg": true, "com.ng": true, "com.pk": true,
	"co.th": true, "in.th": true, "com.es": true, "com.pt": true, "com.gr": true, "com.ro": true,
	"com.ru": true, "org.ru": true, "net.ru": true, "com.de": true, "com.it": true,
}

// managedServiceSuffixes maps the hostname suffixes of managed platforms to the category of
// platform they belong to.
var managedServiceSuffixes = map[string]string{
	"trycloudflare.com": serviceKindTunnel,
	"cfargotunnel.com":  serviceKindTunnel,
	"ngrok.io":          serviceKindTunnel,
	"ngrok.app":         serviceKindTunnel,
	"ngrok-free.app":    serviceKindTunnel,
	"loca.lt":           serviceKindTunnel,
	"localtunnel.me":    serviceKindTunnel,
	"serveo.net":        serviceKindTunnel,
	"tunnelto.dev":      serviceKindTunnel,
	"pagekite.me":       serviceKindTunnel,
	"lhr.life":          serviceKindTunnel,
	"bore.pub":          serviceKindTunnel,
	"devtunnels.ms":     serviceKindTunnel,

	"github.io":           serviceKindFreeHosting,
	"gitlab.io":           serviceKindFreeHosting,
	"pages.dev":           serviceKindFreeHosting,
	"workers.dev":         serviceKindFreeHosting,
	"vercel.app":          serviceKindFreeHosting,
	"netlify.app":         serviceKindFreeHosting,
	"onrender.com":        serviceKindFreeHosting,
	"herokuapp.com":       serviceKindFreeHosting,
	"azurewebsites.net":   serviceKindFreeHosting,
	"web.app":             serviceKindFreeHosting,
	"firebaseapp.com":     serviceKindFreeHosting,
	"amplifyapp.com":      serviceKindFreeHosting,
	"glitch.me":           serviceKindFreeHosting,
	"repl.co":             serviceKindFreeHosting,
	"replit.app":          serviceKindFreeHosting,
	"surge.sh":            serviceKindFreeHosting,
	"neocities.org":       serviceKindFreeHosting,
	"000webhostapp.com":   serviceKindFreeHosting,
	"infinityfreeapp.com": serviceKindFreeHosting,
	"epizy.com":           serviceKindFreeHosting,
	"byethost.com":        serviceKindFreeHosting,
	"altervista.org":      serviceKindFreeHosting,
	"weebly.com":          serviceKindFreeHosting,
	"wixsite.com":         serviceKindFreeHosting,
	"blogspot.com":        serviceKindFreeHosting,
	"webflow.io":          serviceKindFreeHosting,
	"jimdosite.com":       serviceKindFreeHosting,
	"mystrikingly.com":    serviceKindFreeHosting,
	"godaddysites.com":    serviceKindFreeHosting,
	"tilda.ws":            serviceKindFreeHosting,
	"ucoz.net":            serviceKindFreeHosting,
	"r2.dev":              serviceKindFreeHosting,

	"duckdns.org":         serviceKindDynamicDNS,
	"no-ip.org":           serviceKindDynamicDNS,
	"no-ip.com":           serviceKindDynamicDNS,
	"ddns.net":            serviceKindDynamicDNS,
	"hopto.org":           serviceKindDynamicDNS,
	"zapto.org":           serviceKindDynamicDNS,
	"sytes.net":           serviceKindDynamicDNS,
	"myftp.org":           serviceKindDynamicDNS,
	"myftp.biz":           serviceKindDynamicDNS,
	"serveblog.net":       serviceKindDynamicDNS,
	"redirectme.net":      serviceKindDynamicDNS,
	"bounceme.net":        serviceKindDynamicDNS,
	"freedynamicdns.net":  serviceKindDynamicDNS,
	"3utilities.com":      serviceKindDynamicDNS,
	"dynu.net":            serviceKindDynamicDNS,
	"dynv6.net":           serviceKindDynamicDNS,
	"chickenkiller.com":   serviceKindDynamicDNS,
	"crabdance.com":       serviceKindDynamicDNS,
	"mooo.com":            serviceKindDynamicDNS,
	"strangled.net":       serviceKindDynamicDNS,
	"twilightparadox.com": serviceKindDynamicDNS,
}

// freeDNSProviderSuffixes are the zones of nameserver operators that hand out zone hosting for
// free and without verification.
var freeDNSProviderSuffixes = []string{
	"afraid.org",
	"cloudns.net",
	"cloudns.cl",
	"duckdns.org",
	"dynu.com",
	"no-ip.com",
	"freedns.org",
	"zoneedit.com",
	"desec.io",
	"1984.is",
	"dnsexit.com",
	"changeip.com",
}

// dynamicReverseNameMarkers are the substrings that mark a reverse DNS name as belonging to an
// access network rather than to hosting.
var dynamicReverseNameMarkers = []string{
	"dynamic", "dyn-", "dyn.", "dial", "dialup", "dsl", "adsl", "vdsl", "pppoe", "ppp-",
	"cable", "broadband", "wireless", "wimax", "gprs", "lte-", "3g-", "4g-",
	"customer", "clients", "client-", "subscriber", "user-", "users.", "home-", "res-",
	"pool-", "pools.", "cpe-", "cpe.", "static-ip", "ip-", "host-",
}

// abuseProneTopLevelDomains are the top level domains whose registration terms make bulk
// disposable registration cheapest, and which consequently dominate published phishing and
// spam rankings.
var abuseProneTopLevelDomains = map[string]bool{
	"tk": true, "ml": true, "ga": true, "cf": true, "gq": true,
	"top": true, "icu": true, "buzz": true, "cyou": true, "sbs": true, "cfd": true,
	"bond": true, "quest": true, "rest": true, "monster": true, "click": true,
	"work": true, "fit": true, "beauty": true, "hair": true, "skin": true, "makeup": true,
	"autos": true, "boats": true, "homes": true, "motorcycles": true, "yachts": true,
	"zip": true, "mov": true, "lol": true, "cam": true, "uno": true, "gdn": true,
}

// reservedAddressRanges are the ranges that are not globally routable but that the standard
// library's own predicates do not cover, so that an address inside one of them is reported
// with the reason rather than as an ordinary public address.
var reservedAddressRanges = buildReservedAddressRanges()

// buildReservedAddressRanges parses the reserved range table once at start up.
func buildReservedAddressRanges() []modules.ReservedRange {
	definitions := []struct {
		cidr  string
		scope string
	}{
		{"0.0.0.0/8", "unroutable this-network range"},
		{"100.64.0.0/10", "carrier-grade NAT range"},
		{"192.0.0.0/24", "IETF protocol assignments range"},
		{"192.0.2.0/24", "documentation range"},
		{"198.18.0.0/15", "benchmarking range"},
		{"198.51.100.0/24", "documentation range"},
		{"203.0.113.0/24", "documentation range"},
		{"240.0.0.0/4", "reserved range"},
		{"fc00::/7", "unique local range"},
		{"2001:db8::/32", "documentation range"},
	}

	ranges := []modules.ReservedRange{}
	for _, definition := range definitions {
		_, network, err := net.ParseCIDR(definition.cidr)
		if err != nil {
			continue
		}
		ranges = append(ranges, modules.ReservedRange{Network: network, Scope: definition.scope})
	}
	return ranges
}
