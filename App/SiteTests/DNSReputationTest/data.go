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

// managedServiceSuffixes maps the hostname suffixes of managed platforms to the category of
// platform they belong to.
var managedServiceSuffixes = map[string]string{
	"trycloudflare.com":     serviceKindTunnel,
	"cfargotunnel.com":      serviceKindTunnel,
	"ngrok.io":              serviceKindTunnel,
	"ngrok.app":             serviceKindTunnel,
	"ngrok-free.app":        serviceKindTunnel,
	"loca.lt":               serviceKindTunnel,
	"localtunnel.me":        serviceKindTunnel,
	"serveo.net":            serviceKindTunnel,
	"tunnelto.dev":          serviceKindTunnel,
	"pagekite.me":           serviceKindTunnel,
	"lhr.life":              serviceKindTunnel,
	"bore.pub":              serviceKindTunnel,
	"devtunnels.ms":         serviceKindTunnel,
	"ngrok.dev":             serviceKindTunnel,
	"ngrok-free.dev":        serviceKindTunnel,
	"localhost.run":         serviceKindTunnel,
	"serveousercontent.com": serviceKindTunnel,
	"loclx.io":              serviceKindTunnel,
	"pinggy.link":           serviceKindTunnel,
	"zrok.io":               serviceKindTunnel,
	"ts.net":                serviceKindTunnel,
	"sharedwithexpose.com":  serviceKindTunnel,
	"tunnelmole.net":        serviceKindTunnel,
	"loophole.site":         serviceKindTunnel,

	"github.io":              serviceKindFreeHosting,
	"gitlab.io":              serviceKindFreeHosting,
	"pages.dev":              serviceKindFreeHosting,
	"workers.dev":            serviceKindFreeHosting,
	"vercel.app":             serviceKindFreeHosting,
	"netlify.app":            serviceKindFreeHosting,
	"onrender.com":           serviceKindFreeHosting,
	"herokuapp.com":          serviceKindFreeHosting,
	"azurewebsites.net":      serviceKindFreeHosting,
	"web.app":                serviceKindFreeHosting,
	"firebaseapp.com":        serviceKindFreeHosting,
	"amplifyapp.com":         serviceKindFreeHosting,
	"glitch.me":              serviceKindFreeHosting,
	"repl.co":                serviceKindFreeHosting,
	"replit.app":             serviceKindFreeHosting,
	"surge.sh":               serviceKindFreeHosting,
	"neocities.org":          serviceKindFreeHosting,
	"000webhostapp.com":      serviceKindFreeHosting,
	"infinityfreeapp.com":    serviceKindFreeHosting,
	"epizy.com":              serviceKindFreeHosting,
	"byethost.com":           serviceKindFreeHosting,
	"altervista.org":         serviceKindFreeHosting,
	"weebly.com":             serviceKindFreeHosting,
	"wixsite.com":            serviceKindFreeHosting,
	"blogspot.com":           serviceKindFreeHosting,
	"webflow.io":             serviceKindFreeHosting,
	"jimdosite.com":          serviceKindFreeHosting,
	"mystrikingly.com":       serviceKindFreeHosting,
	"godaddysites.com":       serviceKindFreeHosting,
	"tilda.ws":               serviceKindFreeHosting,
	"ucoz.net":               serviceKindFreeHosting,
	"r2.dev":                 serviceKindFreeHosting,
	"fly.dev":                serviceKindFreeHosting,
	"railway.app":            serviceKindFreeHosting,
	"deno.dev":               serviceKindFreeHosting,
	"run.app":                serviceKindFreeHosting,
	"appspot.com":            serviceKindFreeHosting,
	"azurestaticapps.net":    serviceKindFreeHosting,
	"web.core.windows.net":   serviceKindFreeHosting,
	"blob.core.windows.net":  serviceKindFreeHosting,
	"storage.googleapis.com": serviceKindFreeHosting,
	"pythonanywhere.com":     serviceKindFreeHosting,
	"csb.app":                serviceKindFreeHosting,
	"lovable.app":            serviceKindFreeHosting,
	"bitbucket.io":           serviceKindFreeHosting,
	"codeberg.page":          serviceKindFreeHosting,
	"sourceforge.io":         serviceKindFreeHosting,
	"pantheonsite.io":        serviceKindFreeHosting,
	"wpenginepowered.com":    serviceKindFreeHosting,
	"cloudwaysapps.com":      serviceKindFreeHosting,
	"wordpress.com":          serviceKindFreeHosting,
	"squarespace.com":        serviceKindFreeHosting,
	"wixstudio.com":          serviceKindFreeHosting,
	"myshopify.com":          serviceKindFreeHosting,
	"bigcartel.com":          serviceKindFreeHosting,
	"square.site":            serviceKindFreeHosting,
	"carrd.co":               serviceKindFreeHosting,
	"framer.app":             serviceKindFreeHosting,
	"framer.website":         serviceKindFreeHosting,
	"notion.site":            serviceKindFreeHosting,
	"gitbook.io":             serviceKindFreeHosting,
	"readthedocs.io":         serviceKindFreeHosting,
	"ghost.io":               serviceKindFreeHosting,
	"substack.com":           serviceKindFreeHosting,
	"tumblr.com":             serviceKindFreeHosting,
	"livejournal.com":        serviceKindFreeHosting,
	"webnode.page":           serviceKindFreeHosting,
	"yolasite.com":           serviceKindFreeHosting,
	"site123.me":             serviceKindFreeHosting,
	"ucoz.ru":                serviceKindFreeHosting,
	"narod.ru":               serviceKindFreeHosting,
	"tripod.com":             serviceKindFreeHosting,
	"angelfire.com":          serviceKindFreeHosting,
	"rf.gd":                  serviceKindFreeHosting,
	"42web.io":               serviceKindFreeHosting,
	"ipfs.io":                serviceKindFreeHosting,
	"dweb.link":              serviceKindFreeHosting,
	"w3s.link":               serviceKindFreeHosting,
	"nftstorage.link":        serviceKindFreeHosting,

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

	// No-IP's free hostname domains
	"servebeer.com":          serviceKindDynamicDNS,
	"servegame.com":          serviceKindDynamicDNS,
	"serveftp.com":           serviceKindDynamicDNS,
	"servehttp.com":          serviceKindDynamicDNS,
	"servemp3.com":           serviceKindDynamicDNS,
	"servepics.com":          serviceKindDynamicDNS,
	"servequake.com":         serviceKindDynamicDNS,
	"serveminecraft.net":     serviceKindDynamicDNS,
	"servecounterstrike.com": serviceKindDynamicDNS,
	"servehalflife.com":      serviceKindDynamicDNS,
	"serveirc.com":           serviceKindDynamicDNS,
	"myvnc.com":              serviceKindDynamicDNS,
	"myddns.me":              serviceKindDynamicDNS,
	"ddnsking.com":           serviceKindDynamicDNS,
	"gotdns.ch":              serviceKindDynamicDNS,
	"webhop.me":              serviceKindDynamicDNS,
	"hopto.me":               serviceKindDynamicDNS,
	"loginto.me":             serviceKindDynamicDNS,
	"onthewifi.com":          serviceKindDynamicDNS,
	"damnserver.com":         serviceKindDynamicDNS,
	"ditchyourip.com":        serviceKindDynamicDNS,
	"dnsfor.me":              serviceKindDynamicDNS,
	"loseyourip.com":         serviceKindDynamicDNS,
	"myactivedirectory.com":  serviceKindDynamicDNS,
	"mysecuritycamera.com":   serviceKindDynamicDNS,
	"mysecuritycamera.net":   serviceKindDynamicDNS,
	"mysecuritycamera.org":   serviceKindDynamicDNS,
	"workisboring.com":       serviceKindDynamicDNS,

	// Dyn's legacy free hostname domains
	"dyndns.org":    serviceKindDynamicDNS,
	"dyndns.biz":    serviceKindDynamicDNS,
	"dyndns.info":   serviceKindDynamicDNS,
	"homeip.net":    serviceKindDynamicDNS,
	"homelinux.com": serviceKindDynamicDNS,
	"homeunix.com":  serviceKindDynamicDNS,
	"dnsalias.com":  serviceKindDynamicDNS,
	"dnsalias.net":  serviceKindDynamicDNS,
	"dnsalias.org":  serviceKindDynamicDNS,
	"selfip.com":    serviceKindDynamicDNS,
	"is-a-geek.com": serviceKindDynamicDNS,
	"kicks-ass.net": serviceKindDynamicDNS,
	"mine.nu":       serviceKindDynamicDNS,

	// FreeDNS (afraid.org) shared domains
	"us.to":           serviceKindDynamicDNS,
	"uk.to":           serviceKindDynamicDNS,
	"jumpingcrab.com": serviceKindDynamicDNS,
	"ignorelist.com":  serviceKindDynamicDNS,

	// Dynu, dynv6, deSEC and other free providers
	"freeddns.org":  serviceKindDynamicDNS,
	"mywire.org":    serviceKindDynamicDNS,
	"kozow.com":     serviceKindDynamicDNS,
	"gleeze.com":    serviceKindDynamicDNS,
	"ddnsfree.com":  serviceKindDynamicDNS,
	"v6.rocks":      serviceKindDynamicDNS,
	"dedyn.io":      serviceKindDynamicDNS,
	"nsupdate.info": serviceKindDynamicDNS,
	"spdns.de":      serviceKindDynamicDNS,
	"ddnss.de":      serviceKindDynamicDNS,
	"ydns.eu":       serviceKindDynamicDNS,
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
	"he.net",
	"dynv6.com",
	"desec.org",
	"ydns.eu",
	"freenom.com",
	"byet.org",
	"epizy.com",
}

// dynamicReverseNameMarkers are the substrings that mark a reverse DNS name as belonging to an
// access network rather than to hosting.
var dynamicReverseNameMarkers = []string{
	"dynamic", "dyn-", "dyn.", "dial", "dialup", "dsl", "adsl", "vdsl", "pppoe", "ppp-",
	"cable", "broadband", "wireless", "wimax", "gprs", "lte-", "3g-", "4g-",
	"customer", "clients", "client-", "subscriber", "user-", "users.", "home-", "res-",
	"pool-", "pools.", "cpe-", "cpe.", "static-ip", "ip-", "host-",
	"dhcp", "dynip", "xdsl", "ftth", "gpon", "cgnat", "residential", "kabel", "bredband",
	"wlan", "umts", "5g-", "lte.", "cust-", "hsd1.", "dip0.",
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
	"xyz": true, "shop": true, "online": true, "site": true, "store": true, "live": true,
	"vip": true, "club": true, "today": true, "life": true, "world": true, "space": true,
	"website": true, "fun": true, "link": true, "best": true, "ltd": true, "host": true,
	"press": true, "bar": true, "pw": true, "cc": true, "ws": true, "su": true,
	"loan": true, "win": true, "bid": true, "date": true, "download": true, "racing": true,
	"review": true, "stream": true, "trade": true, "party": true, "science": true,
	"cricket": true, "faith": true, "accountant": true, "men": true, "webcam": true, "kim": true,
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
