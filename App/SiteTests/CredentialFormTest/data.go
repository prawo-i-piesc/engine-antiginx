package CredentialFormTest

import (
	"Engine-AntiGinx/App/SiteTests/CredentialFormTest/modules"
	"regexp"
)

// markupPatterns are the expressions forms, fields and scripts are extracted with, compiled
// once at start up.
var markupPatterns = modules.MarkupPatterns{
	Comment:   regexp.MustCompile(`(?s)<!--.*?-->`),
	Script:    regexp.MustCompile(`(?is)<script\b([^>]*)>(.*?)</script\s*>`),
	FormOpen:  regexp.MustCompile(`(?is)<form\b[^>]*>`),
	FormClose: regexp.MustCompile(`(?is)</form\s*>`),
	Control:   regexp.MustCompile(`(?is)<(input|select|button|textarea)\b[^>]*>`),
	BaseTag:   regexp.MustCompile(`(?is)<base\b[^>]*>`),
	Attribute: regexp.MustCompile(`(?is)([a-z][a-z0-9-]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))`),
}

// fieldPatterns recognise a sensitive field by its name, id, placeholder or label. They are
// matched against identifiers split into lowercase words, so cardNumber, card_number and
// card-number all read "card number". Card is tried before one-time code, and one-time code
// before password, so "security code" is a card field and "sms password" a one-time code.
var fieldPatterns = []modules.FieldPattern{
	{Kind: modules.FieldCard, Pattern: regexp.MustCompile(`(?:^|\s)(?:card ?(?:number|num|no|nr|code|cvv|holder ?number)|cardnumber|ccnum|ccn|cc ?(?:number|num|no|exp|csc|cvv|cvc)|credit ?card|debit ?card|cvv2?|cvc2?|csc|cvn|security ?code|exp ?(?:date|month|year)|expdate|expiry|expiration|mm ?yy|numer ?karty|nr ?karty|data ?wa[zż]no[sś]ci|kod ?cvv|kod ?cvc)(?:\s|$)`)},
	{Kind: modules.FieldOTP, Pattern: regexp.MustCompile(`(?:^|\s)(?:otp|one ?time ?(?:code|password|pin)|2fa|two ?factor|mfa|totp|sms ?(?:code|password|pin)|verification ?code|verify ?code|auth ?code|authentication ?code|authori[sz]ation ?code|pin|pin ?code|kod ?sms|kod ?weryfikacyjny|kod ?autoryzacyjny|kod ?jednorazowy)(?:\s|$)`)},
	{Kind: modules.FieldPassword, Pattern: regexp.MustCompile(`(?:^|\s)(?:password|passwort|passwd|passcode|pass|pwd|pswd|has[lł]o|kennwort|contrase[nñ]a|senha|mot ?de ?passe|parola|wachtwoord)(?:\s|$)`)},
}

// autocompleteKinds maps the autocomplete tokens browsers fill secrets into to the kind of
// secret they hold.
var autocompleteKinds = map[string]string{
	"current-password": modules.FieldPassword,
	"new-password":     modules.FieldPassword,
	"cc-number":        modules.FieldCard,
	"cc-csc":           modules.FieldCard,
	"cc-exp":           modules.FieldCard,
	"cc-exp-month":     modules.FieldCard,
	"cc-exp-year":      modules.FieldCard,
	"one-time-code":    modules.FieldOTP,
}

// ignoredInputTypes are input types a person never types a secret into.
var ignoredInputTypes = map[string]bool{
	"hidden": true, "submit": true, "button": true, "reset": true, "image": true,
	"checkbox": true, "radio": true, "file": true, "range": true, "color": true,
}

// executableScriptTypes are the <script type> values a browser runs as JavaScript. Anything
// else — JSON-LD, templates — is data and is not inspected.
var executableScriptTypes = map[string]bool{
	"":                       true,
	"text/javascript":        true,
	"application/javascript": true,
	"application/ecmascript": true,
	"text/ecmascript":        true,
	"text/jscript":           true,
	"module":                 true,
}

// scriptPatterns recognise a script that sends data somewhere and one that reads what was
// typed into the page.
var scriptPatterns = modules.ScriptPatterns{
	Sender:    regexp.MustCompile(`(?i)\bfetch\s*\(|XMLHttpRequest|\$\.(?:ajax|post|get|getJSON)\s*\(|\baxios\b|sendBeacon\s*\(|new\s+Image\s*\(|\bemailjs\.send`),
	ValueRead: regexp.MustCompile(`(?i)\.value\b|\bFormData\b|\.serialize(?:Array)?\s*\(|\.val\s*\(\s*\)|\.elements\b`),
}

// collectors are the services that receive form data on someone else's behalf. A page on its
// own site has no reason to hand a password, a card number or a one-time code to any of them.
// Host matches the host and its subdomains; Path, when set, must prefix the path.
var collectors = []modules.Collector{
	{Name: "Telegram Bot API", Kind: modules.CollectorMessenger, Host: "api.telegram.org", Path: "/bot"},
	{Name: "Discord webhook", Kind: modules.CollectorMessenger, Host: "discord.com", Path: "/api/webhooks"},
	{Name: "Discord webhook", Kind: modules.CollectorMessenger, Host: "discordapp.com", Path: "/api/webhooks"},
	{Name: "Slack webhook", Kind: modules.CollectorMessenger, Host: "hooks.slack.com", Path: "/services"},

	{Name: "Formspree", Kind: modules.CollectorFormBackend, Host: "formspree.io"},
	{Name: "Google Forms", Kind: modules.CollectorFormBackend, Host: "docs.google.com", Path: "/forms"},
	{Name: "Google Forms", Kind: modules.CollectorFormBackend, Host: "forms.gle"},
	{Name: "Google Apps Script", Kind: modules.CollectorFormBackend, Host: "script.google.com", Path: "/macros"},
	{Name: "EmailJS", Kind: modules.CollectorFormBackend, Host: "api.emailjs.com"},
	{Name: "Getform", Kind: modules.CollectorFormBackend, Host: "getform.io"},
	{Name: "FormSubmit", Kind: modules.CollectorFormBackend, Host: "formsubmit.co"},
	{Name: "Basin", Kind: modules.CollectorFormBackend, Host: "usebasin.com"},
	{Name: "Web3Forms", Kind: modules.CollectorFormBackend, Host: "api.web3forms.com"},
	{Name: "Formcarry", Kind: modules.CollectorFormBackend, Host: "formcarry.com"},
	{Name: "Formspark", Kind: modules.CollectorFormBackend, Host: "submit-form.com"},
	{Name: "FormKeep", Kind: modules.CollectorFormBackend, Host: "formkeep.com"},
	{Name: "Jotform", Kind: modules.CollectorFormBackend, Host: "submit.jotform.com"},
	{Name: "SheetDB", Kind: modules.CollectorFormBackend, Host: "sheetdb.io"},

	{Name: "Webhook.site", Kind: modules.CollectorRequestCatcher, Host: "webhook.site"},
	{Name: "Pipedream", Kind: modules.CollectorRequestCatcher, Host: "pipedream.net"},
	{Name: "Beeceptor", Kind: modules.CollectorRequestCatcher, Host: "beeceptor.com"},
	{Name: "Request Catcher", Kind: modules.CollectorRequestCatcher, Host: "requestcatcher.com"},
	{Name: "ngrok tunnel", Kind: modules.CollectorRequestCatcher, Host: "ngrok.io"},
	{Name: "ngrok tunnel", Kind: modules.CollectorRequestCatcher, Host: "ngrok-free.app"},
	{Name: "ngrok tunnel", Kind: modules.CollectorRequestCatcher, Host: "ngrok.app"},
	{Name: "Cloudflare quick tunnel", Kind: modules.CollectorRequestCatcher, Host: "trycloudflare.com"},
}

// processors are identity providers and payment gateways that legitimately receive a login
// or a card form posted from another site's page.
var processors = map[string]string{
	"paypal.com":                "PayPal",
	"stripe.com":                "Stripe",
	"adyen.com":                 "Adyen",
	"braintreegateway.com":      "Braintree",
	"checkout.com":              "Checkout.com",
	"payu.com":                  "PayU",
	"przelewy24.pl":             "Przelewy24",
	"tpay.com":                  "Tpay",
	"dotpay.pl":                 "Dotpay",
	"auth0.com":                 "Auth0",
	"okta.com":                  "Okta",
	"onelogin.com":              "OneLogin",
	"login.microsoftonline.com": "Microsoft Entra ID",
	"accounts.google.com":       "Google Accounts",
	"appleid.apple.com":         "Apple ID",
}
