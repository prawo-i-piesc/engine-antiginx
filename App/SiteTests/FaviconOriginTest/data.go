package FaviconOriginTest

import (
	"Engine-AntiGinx/App/SiteTests/FaviconOriginTest/modules"
	"regexp"
)

// markupPatterns are the expressions icon declarations are extracted with, compiled once at
// start up.
var markupPatterns = modules.MarkupPatterns{
	Comment:   regexp.MustCompile(`(?s)<!--.*?-->`),
	LinkTag:   regexp.MustCompile(`(?is)<link\b[^>]*>`),
	BaseTag:   regexp.MustCompile(`(?is)<base\b[^>]*>`),
	Attribute: regexp.MustCompile(`(?is)([a-z][a-z0-9-]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))`),
}

// iconRelations are the rel tokens that declare a page icon to a browser or a home screen.
var iconRelations = map[string]bool{
	"icon":                         true,
	"apple-touch-icon":             true,
	"apple-touch-icon-precomposed": true,
	"mask-icon":                    true,
	"fluid-icon":                   true,
}

// brandDomains maps the brands phishing kits most often borrow icons from to every domain the
// brand publishes pages or assets under. A page on one of these domains may use the brand's
// icons; any other page doing so is presenting itself as the brand.
var brandDomains = map[string][]string{
	"google":     {"google.com", "gstatic.com", "googleusercontent.com", "gmail.com", "withgoogle.com", "youtube.com", "ytimg.com"},
	"microsoft":  {"microsoft.com", "microsoftonline.com", "live.com", "outlook.com", "office.com", "office.net", "office365.com", "msauth.net", "msftauth.net", "s-microsoft.com", "sharepoint.com", "onedrive.com", "bing.com", "skype.com", "xbox.com", "linkedin.com", "licdn.com"},
	"apple":      {"apple.com", "icloud.com", "cdn-apple.com", "mzstatic.com"},
	"amazon":     {"amazon.com", "amazon.co.uk", "amazon.de", "amazon.pl", "media-amazon.com", "ssl-images-amazon.com", "awsstatic.com"},
	"meta":       {"facebook.com", "fbcdn.net", "instagram.com", "cdninstagram.com", "messenger.com", "whatsapp.com", "whatsapp.net"},
	"x":          {"x.com", "twitter.com", "twimg.com"},
	"paypal":     {"paypal.com", "paypalobjects.com", "venmo.com"},
	"stripe":     {"stripe.com", "stripe.network"},
	"netflix":    {"netflix.com", "nflxext.com", "nflximg.net"},
	"dropbox":    {"dropbox.com", "dropboxstatic.com"},
	"docusign":   {"docusign.com", "docusign.net"},
	"adobe":      {"adobe.com", "adobelogin.com"},
	"github":     {"github.com", "githubassets.com"},
	"steam":      {"steampowered.com", "steamcommunity.com", "steamstatic.com"},
	"allegro":    {"allegro.pl", "allegrostatic.com", "allegroimg.com"},
	"olx":        {"olx.pl", "olxcdn.com"},
	"inpost":     {"inpost.pl", "inpost.eu"},
	"pkobp":      {"pkobp.pl", "ipko.pl"},
	"mbank":      {"mbank.pl"},
	"santander":  {"santander.pl", "santander.com"},
	"ing":        {"ing.pl", "ing.com"},
	"pekao":      {"pekao.com.pl"},
	"revolut":    {"revolut.com"},
	"dhl":        {"dhl.com", "dhl.de"},
	"dpd":        {"dpd.com", "dpd.com.pl"},
	"binance":    {"binance.com", "bnbstatic.com"},
	"coinbase":   {"coinbase.com"},
	"metamask":   {"metamask.io"},
	"gov-pl":     {"gov.pl"},
	"cloudflare": {"cloudflare.com"},
}

// assetHostSuffixes are hostnames of content delivery networks and site platforms that serve
// icons on behalf of their customers, mapped to the provider's name. They are matched before
// brands, so a public CDN run by a brand is not mistaken for the brand's own assets.
var assetHostSuffixes = map[string]string{
	"cdnjs.cloudflare.com":       "cdnjs",
	"imagedelivery.net":          "Cloudflare Images",
	"cloudfront.net":             "Amazon CloudFront",
	"amazonaws.com":              "Amazon S3",
	"akamaihd.net":               "Akamai",
	"akamaized.net":              "Akamai",
	"fastly.net":                 "Fastly",
	"azureedge.net":              "Azure CDN",
	"blob.core.windows.net":      "Azure Storage",
	"storage.googleapis.com":     "Google Cloud Storage",
	"firebasestorage.app":        "Firebase Storage",
	"jsdelivr.net":               "jsDelivr",
	"unpkg.com":                  "unpkg",
	"b-cdn.net":                  "BunnyCDN",
	"imgix.net":                  "imgix",
	"cloudinary.com":             "Cloudinary",
	"ctfassets.net":              "Contentful",
	"wp.com":                     "WordPress.com",
	"wordpress.com":              "WordPress.com",
	"w.org":                      "WordPress.org",
	"squarespace-cdn.com":        "Squarespace",
	"squarespace.com":            "Squarespace",
	"wixstatic.com":              "Wix",
	"parastorage.com":            "Wix",
	"cdn.shopify.com":            "Shopify",
	"shopifycdn.net":             "Shopify",
	"website-files.com":          "Webflow",
	"webflow.com":                "Webflow",
	"framerusercontent.com":      "Framer",
	"hubspotusercontent.net":     "HubSpot",
	"hubspotusercontent-na1.net": "HubSpot",
	"hsappstatic.net":            "HubSpot",
	"vercel.app":                 "Vercel",
	"netlify.app":                "Netlify",
	"github.io":                  "GitHub Pages",
	"gitlab.io":                  "GitLab Pages",
	"raw.githubusercontent.com":  "GitHub raw content",
}
