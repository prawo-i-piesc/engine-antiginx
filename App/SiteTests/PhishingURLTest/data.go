package PhishingURLTest

// Reference datasets the phishing analysis recognises a hostname and a query string
// against. They are the part of this test that dates fastest — brands appear, phishing
// kits change the parameter names they use — so they are kept here, apart from the logic
// that reads them, and are handed to the analysis modules by core.go.

var popularDomainDatabase = map[string][]string{
	"google": {
		"google.com", "gmail.com", "googlemail.com", "google.co.uk", "google.de", "google.fr", "google.pl", "google.it", "google.es", "google.ca", "google.com.br", "google.com.au",
	},
	"microsoft": {
		"microsoft.com", "live.com", "outlook.com", "office.com", "office365.com", "microsoftonline.com", "skype.com", "xbox.com", "bing.com", "linkedin.com",
	},
	"apple": {
		"apple.com", "icloud.com", "me.com", "mac.com", "itunes.com",
	},
	"amazon": {
		"amazon.com", "amazon.co.uk", "amazon.de", "amazon.fr", "amazon.pl", "amazon.it", "amazon.es", "amazon.ca", "amazon.in", "amazon.com.au", "amazonaws.com",
	},
	"meta": {
		"facebook.com", "fb.com", "messenger.com", "instagram.com", "threads.net", "whatsapp.com",
	},
	"x": {
		"x.com", "twitter.com", "t.co",
	},
	"youtube": {
		"youtube.com", "youtu.be",
	},
	"tiktok": {
		"tiktok.com",
	},
	"snapchat": {
		"snapchat.com",
	},
	"paypal": {
		"paypal.com", "paypalobjects.com", "venmo.com", "braintreepayments.com",
	},
	"stripe": {
		"stripe.com",
	},
	"wise": {
		"wise.com",
	},
	"revolut": {
		"revolut.com",
	},
	"payoneer": {
		"payoneer.com",
	},
	"cashapp": {
		"cash.app",
	},
	"chase": {
		"chase.com", "jpmorganchase.com",
	},
	"bankofamerica": {
		"bankofamerica.com",
	},
	"wellsfargo": {
		"wellsfargo.com",
	},
	"citi": {
		"citi.com", "citibank.com",
	},
	"capitalone": {
		"capitalone.com",
	},
	"hsbc": {
		"hsbc.com",
	},
	"santander": {
		"santander.com",
	},
	"americanexpress": {
		"americanexpress.com", "amex.com",
	},
	"visa": {
		"visa.com",
	},
	"mastercard": {
		"mastercard.com",
	},
	"github": {
		"github.com", "github.io",
	},
	"gitlab": {
		"gitlab.com",
	},
	"bitbucket": {
		"bitbucket.org",
	},
	"atlassian": {
		"atlassian.com", "jira.com", "trello.com",
	},
	"docker": {
		"docker.com", "docker.io",
	},
	"cloudflare": {
		"cloudflare.com",
	},
	"aws": {
		"aws.amazon.com", "amazonaws.com",
	},
	"azure": {
		"azure.com", "windowsazure.com",
	},
	"gcp": {
		"cloud.google.com", "withgoogle.com",
	},
	"dropbox": {
		"dropbox.com",
	},
	"slack": {
		"slack.com",
	},
	"zoom": {
		"zoom.us",
	},
	"discord": {
		"discord.com", "discord.gg",
	},
	"telegram": {
		"telegram.org", "t.me",
	},
	"netflix": {
		"netflix.com",
	},
	"spotify": {
		"spotify.com",
	},
	"disney": {
		"disneyplus.com", "disney.com",
	},
	"steam": {
		"steampowered.com", "steamcommunity.com",
	},
	"epicgames": {
		"epicgames.com", "unrealengine.com",
	},
	"ea": {
		"ea.com", "origin.com",
	},
	"nintendo": {
		"nintendo.com",
	},
	"sony": {
		"sony.com", "playstation.com",
	},
	"booking": {
		"booking.com",
	},
	"airbnb": {
		"airbnb.com",
	},
	"uber": {
		"uber.com", "ubereats.com",
	},
	"lyft": {
		"lyft.com",
	},
	"ebay": {
		"ebay.com", "ebay.co.uk", "ebay.de", "ebay.fr",
	},
	"aliexpress": {
		"aliexpress.com",
	},
	"etsy": {
		"etsy.com",
	},
	"wikipedia": {
		"wikipedia.org", "wikimedia.org",
	},
	"adobe": {
		"adobe.com", "behance.net",
	},
	"canva": {
		"canva.com",
	},
	"salesforce": {
		"salesforce.com",
	},
	"shopify": {
		"shopify.com", "myshopify.com",
	},
	"coinbase": {
		"coinbase.com",
	},
	"binance": {
		"binance.com",
	},
	"kraken": {
		"kraken.com",
	},
	"metamask": {
		"metamask.io",
	},
	"openai": {
		"openai.com", "chatgpt.com",
	},
	"notion": {
		"notion.so",
	},
	"figma": {
		"figma.com",
	},
	"reddit": {
		"reddit.com",
	},
	"quora": {
		"quora.com",
	},
	"yahoo": {
		"yahoo.com",
	},
}

var popularLetterReplacementDatabase = map[string][]string{
	"m": {"rn", "nn"},
	"w": {"vv"},
	"d": {"cl"},
	"n": {"ri"},
	"u": {"v"},
	"v": {"u"},
	"k": {"lc"},
	"h": {"lh", "ii"},
	"b": {"6", "8"},
	"g": {"9", "q"},
	"q": {"g"},
	"l": {"1", "i"},
	"i": {"1", "l"},
	"o": {"0"},
	"e": {"3"},
	"a": {"4"},
	"s": {"5"},
	"t": {"7"},
	"z": {"2"},
	"x": {"kz"},
}

var confusableRuneDatabase = map[rune]rune{
	'а': 'a', // Cyrillic a
	'е': 'e', // Cyrillic e
	'о': 'o', // Cyrillic o
	'р': 'p', // Cyrillic er
	'с': 'c', // Cyrillic es
	'у': 'y', // Cyrillic u
	'х': 'x', // Cyrillic ha
	'к': 'k', // Cyrillic ka
	'м': 'm', // Cyrillic em
	'т': 't', // Cyrillic te
	'в': 'b', // Cyrillic ve
	'н': 'h', // Cyrillic en
	'і': 'i', // Cyrillic i
	'ј': 'j', // Cyrillic je
	'ԁ': 'd', // Cyrillic-like d
	'գ': 'g', // Armenian g
	'ο': 'o', // Greek omicron
	'ρ': 'p', // Greek rho
	'ν': 'v', // Greek nu
	'τ': 't', // Greek tau
	'ι': 'i', // Greek iota
	'κ': 'k', // Greek kappa
	'χ': 'x', // Greek chi
	'ʟ': 'l', // Latin small capital L
}

// credentialParameterDatabase lists query parameter names that carry an actual secret.
var credentialParameterDatabase = []string{
	"password", "passwd", "pwd", "pass", "passphrase", "userpassword", "userpass",
	"secret", "clientsecret", "appsecret", "privatekey", "credentials", "creds",
}

// sensitiveParameterDatabase lists query parameter names that carry authentication or payment
// material.
var sensitiveParameterDatabase = []string{
	"token", "accesstoken", "idtoken", "refreshtoken", "authtoken", "auth",
	"authorization", "apikey", "apitoken", "session", "sessionid", "jsessionid",
	"phpsessid", "sid", "otp", "mfa", "2fa", "pin", "code", "cardnumber",
	"creditcard", "cvv", "cvc", "iban", "ssn",
}

// identityParameterDatabase lists parameter names used by phishing kits to pre-fill the victim
// identity, so the landing page can greet the target by name and look legitimate.
var identityParameterDatabase = []string{
	"email", "mail", "emailaddress", "username", "user", "usr", "userid",
	"login", "account", "accountid", "customerid",
}

// redirectParameterDatabase lists parameter names commonly used to carry a redirection target.
var redirectParameterDatabase = []string{
	"redirect", "redirecturi", "redirecturl", "returnurl", "returnto", "return",
	"continue", "next", "goto", "dest", "destination", "target", "callback",
	"forward", "url", "uri", "link", "out",
}

// dangerousSchemeDatabase lists URL schemes that must never appear inside a parameter value.
var dangerousSchemeDatabase = []string{
	"javascript:", "data:", "vbscript:", "file:",
}

// phishingPathKeywordDatabase lists path fragments heavily used by phishing kits to make a URL
// look like an official account operation.
var phishingPathKeywordDatabase = []string{
	"secure", "verify", "verification", "confirm", "validate", "update",
	"unlock", "recover", "restore", "suspended", "signin", "webscr",
}
