package URLhausTest

// abusedLegitimateListings are the Spamhaus DBL classifications URLhaus reports for a domain
// that is a legitimate service somebody abused - a file host, a code forge, a URL shortener.
// Listed URLs on such a host say nothing about the rest of it.
var abusedLegitimateListings = []string{
	"abused_legit_spam",
	"abused_legit_malware",
	"abused_legit_phishing",
	"abused_legit_botnetcc",
	"abused_redirector",
}

// maliciousListings are the Spamhaus DBL classifications of a domain operated for abuse.
var maliciousListings = []string{
	"spammer_domain",
	"phishing_domain",
	"botnet_cc_domain",
}
