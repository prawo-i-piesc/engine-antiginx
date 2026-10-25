package ServerHeaderTest

import "Engine-AntiGinx/App/SiteTests/ServerHeaderTest/modules"

// exposureHeaderNames are the headers read from the response. Each one names the software
// behind the site by its value or by being sent at all; request identifiers and generic
// proxy headers are left out, since every header here counts towards the exposure grade.
var exposureHeaderNames = []string{
	// Server and framework banners
	"Server",
	"X-Powered-By",
	"X-Powered-CMS",
	"X-Powered-By-Plesk",
	"X-AspNet-Version",
	"X-AspNetMvc-Version",
	"X-SourceFiles",
	"X-Framework",
	"X-Generator",
	"X-Runtime",
	"X-Application-Context",

	// Content management systems and shop platforms
	"X-Drupal-Cache",
	"X-Drupal-Dynamic-Cache",
	"X-Pingback",
	"X-Redirect-By",
	"X-Magento-Cache-Debug",
	"X-Shopify-Stage",
	"Liferay-Portal",
	"MicrosoftSharePointTeamServices",
	"X-OWA-Version",

	// Build servers
	"X-Jenkins",
	"X-Hudson",

	// Caches, accelerators and hosting platforms
	"X-Mod-Pagespeed",
	"X-Page-Speed",
	"X-Varnish",
	"X-Served-By",
	"X-Cache",
	"X-Rack-Cache",
	"X-Litespeed-Cache",
	"X-Turbo-Charged-By",
	"X-Nextjs-Cache",
	"X-Vercel-Cache",

	// Gateways, service meshes and web application firewalls
	"X-Envoy-Upstream-Service-Time",
	"X-Kong-Upstream-Latency",
	"X-Sucuri-ID",
}

// technologySignatures map a header to the technologies its value can name, keyed by the
// lowercase header name. Keywords are matched as substrings of the lowercased value, so each
// is specific enough not to occur inside an unrelated product name.
var technologySignatures = map[string][]modules.Signature{
	"server": {
		// General-purpose web servers
		{Keyword: "apache", Technology: "Apache", VersionToken: "apache"},
		{Keyword: "nginx", Technology: "Nginx", VersionToken: "nginx"},
		{Keyword: "openresty", Technology: "OpenResty", VersionToken: "openresty"},
		{Keyword: "tengine", Technology: "Tengine", VersionToken: "tengine"},
		{Keyword: "litespeed", Technology: "LiteSpeed", VersionToken: "litespeed"},
		{Keyword: "lighttpd", Technology: "Lighttpd", VersionToken: "lighttpd"},
		{Keyword: "caddy", Technology: "Caddy", VersionToken: "caddy"},
		{Keyword: "iis", Technology: "Microsoft IIS", VersionToken: "iis"},
		{Keyword: "microsoft-httpapi", Technology: "Microsoft HTTP.sys", VersionToken: "microsoft-httpapi"},
		{Keyword: "ibm_http_server", Technology: "IBM HTTP Server", VersionToken: "ibm_http_server"},

		// Application servers and runtimes
		{Keyword: "apache-coyote", Technology: "Apache Tomcat"},
		{Keyword: "jetty", Technology: "Jetty", VersionToken: "jetty"},
		{Keyword: "glassfish", Technology: "GlassFish", VersionToken: "glassfish"},
		{Keyword: "wildfly", Technology: "WildFly", VersionToken: "wildfly"},
		{Keyword: "jboss", Technology: "JBoss", VersionToken: "jboss"},
		{Keyword: "weblogic", Technology: "Oracle WebLogic", VersionToken: "weblogic"},
		{Keyword: "resin", Technology: "Resin", VersionToken: "resin"},
		{Keyword: "kestrel", Technology: "Kestrel"},
		{Keyword: "cowboy", Technology: "Cowboy"},
		{Keyword: "phusion_passenger", Technology: "Phusion Passenger", VersionToken: "phusion_passenger"},
		{Keyword: "gunicorn", Technology: "Gunicorn", VersionToken: "gunicorn"},
		{Keyword: "uvicorn", Technology: "Uvicorn", VersionToken: "uvicorn"},
		{Keyword: "hypercorn", Technology: "Hypercorn", VersionToken: "hypercorn"},
		{Keyword: "waitress", Technology: "Waitress", VersionToken: "waitress"},
		{Keyword: "werkzeug", Technology: "Werkzeug", VersionToken: "werkzeug"},
		{Keyword: "tornadoserver", Technology: "Tornado", VersionToken: "tornadoserver"},
		{Keyword: "cherrypy", Technology: "CherryPy", VersionToken: "cherrypy"},

		// Proxies, caches, load balancers and hosting platforms
		{Keyword: "envoy", Technology: "Envoy"},
		{Keyword: "squid", Technology: "Squid", VersionToken: "squid"},
		{Keyword: "varnish", Technology: "Varnish Cache"},
		{Keyword: "awselb", Technology: "AWS Elastic Load Balancing"},
		{Keyword: "amazons3", Technology: "Amazon S3"},
		{Keyword: "cloudfront", Technology: "Amazon CloudFront"},
		{Keyword: "akamaighost", Technology: "Akamai"},
		{Keyword: "bigip", Technology: "F5 BIG-IP"},
		{Keyword: "cloudflare", Technology: "Cloudflare"},
		{Keyword: "ddos-guard", Technology: "DDoS-Guard"},
		{Keyword: "sucuri", Technology: "Sucuri"},
		{Keyword: "vercel", Technology: "Vercel"},
		{Keyword: "netlify", Technology: "Netlify"},
		{Keyword: "github.com", Technology: "GitHub Pages"},
	},
	"x-powered-by": {
		// Languages and runtimes
		{Keyword: "php", Technology: "PHP", VersionToken: "php"},
		{Keyword: "asp.net", Technology: "ASP.NET", VersionToken: "asp.net"},
		{Keyword: "hhvm", Technology: "HHVM", VersionToken: "hhvm"},
		{Keyword: "servlet", Technology: "Java Servlet", VersionToken: "servlet"},
		{Keyword: "jsp/", Technology: "JavaServer Pages", VersionToken: "jsp"},
		{Keyword: "undertow", Technology: "Undertow", VersionToken: "undertow"},
		{Keyword: "jboss", Technology: "JBoss", VersionToken: "jboss"},
		{Keyword: "phusion passenger", Technology: "Phusion Passenger", VersionToken: "phusion passenger"},
		{Keyword: "zend", Technology: "Zend Server", VersionToken: "zend"},

		// Web frameworks
		{Keyword: "express", Technology: "Express.js"},
		{Keyword: "next.js", Technology: "Next.js", VersionToken: "next.js"},
		{Keyword: "nuxt", Technology: "Nuxt"},
		{Keyword: "django", Technology: "Django"},
		{Keyword: "flask", Technology: "Flask"},
		{Keyword: "laravel", Technology: "Laravel"},
		{Keyword: "rails", Technology: "Ruby on Rails"},
		{Keyword: "spring", Technology: "Spring Framework"},

		// Content management systems and their plugins
		{Keyword: "craft cms", Technology: "Craft CMS"},
		{Keyword: "strapi", Technology: "Strapi"},
		{Keyword: "w3 total cache", Technology: "W3 Total Cache", VersionToken: "w3 total cache"},
		{Keyword: "wp engine", Technology: "WP Engine"},
		{Keyword: "plesk", Technology: "Plesk"},
	},
	"x-powered-cms": {
		{Keyword: "bitrix", Technology: "1C-Bitrix"},
	},
	"x-generator": {
		{Keyword: "drupal", Technology: "Drupal", VersionToken: "drupal"},
		{Keyword: "wordpress", Technology: "WordPress", VersionToken: "wordpress"},
	},
	"x-redirect-by": {
		{Keyword: "wordpress", Technology: "WordPress"},
		{Keyword: "yoast", Technology: "Yoast SEO"},
	},
	"x-turbo-charged-by": {
		{Keyword: "litespeed", Technology: "LiteSpeed"},
	},
}

// directTechnologyHeaders name a technology by being present at all.
var directTechnologyHeaders = map[string]modules.DirectHeader{
	"x-aspnet-version":                {Technology: "ASP.NET", ValueIsVersion: true},
	"x-aspnetmvc-version":             {Technology: "ASP.NET MVC", ValueIsVersion: true},
	"x-sourcefiles":                   {Technology: "IIS Express"},
	"x-powered-by-plesk":              {Technology: "Plesk"},
	"x-application-context":           {Technology: "Spring Boot"},
	"x-runtime":                       {Technology: "Dynamic Runtime", ValueIsVersion: true},
	"x-drupal-cache":                  {Technology: "Drupal"},
	"x-drupal-dynamic-cache":          {Technology: "Drupal"},
	"x-pingback":                      {Technology: "WordPress"},
	"x-magento-cache-debug":           {Technology: "Magento"},
	"x-shopify-stage":                 {Technology: "Shopify"},
	"liferay-portal":                  {Technology: "Liferay", ValueIsVersion: true},
	"microsoftsharepointteamservices": {Technology: "Microsoft SharePoint", ValueIsVersion: true},
	"x-owa-version":                   {Technology: "Outlook Web App", ValueIsVersion: true},
	"x-jenkins":                       {Technology: "Jenkins", ValueIsVersion: true},
	"x-hudson":                        {Technology: "Hudson", ValueIsVersion: true},
	"x-mod-pagespeed":                 {Technology: "Google PageSpeed", ValueIsVersion: true},
	"x-page-speed":                    {Technology: "Google PageSpeed", ValueIsVersion: true},
	"x-varnish":                       {Technology: "Varnish Cache"},
	"x-rack-cache":                    {Technology: "Rack Cache"},
	"x-litespeed-cache":               {Technology: "LiteSpeed Cache"},
	"x-nextjs-cache":                  {Technology: "Next.js"},
	"x-vercel-cache":                  {Technology: "Vercel"},
	"x-envoy-upstream-service-time":   {Technology: "Envoy"},
	"x-kong-upstream-latency":         {Technology: "Kong Gateway"},
	"x-sucuri-id":                     {Technology: "Sucuri"},
}
