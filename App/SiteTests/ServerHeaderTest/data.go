package ServerHeaderTest

import "Engine-AntiGinx/App/SiteTests/ServerHeaderTest/modules"

// exposureHeaderNames are the headers read from the response.
var exposureHeaderNames = []string{
	"Server",
	"X-Powered-By",
	"X-AspNet-Version",
	"X-AspNetMvc-Version",
	"X-Framework",
	"X-Generator",
	"X-Drupal-Cache",
	"X-Mod-Pagespeed",
	"X-Varnish",
	"X-Served-By",
	"X-Cache",
	"X-Runtime",
}

// technologySignatures map a header to the technologies its value can name, keyed by the
// lowercase header name.
var technologySignatures = map[string][]modules.Signature{
	"server": {
		{Keyword: "apache", Technology: "Apache", VersionToken: "apache"},
		{Keyword: "nginx", Technology: "Nginx", VersionToken: "nginx"},
		{Keyword: "iis", Technology: "Microsoft IIS", VersionToken: "iis"},
		{Keyword: "cloudflare", Technology: "Cloudflare"},
		{Keyword: "gunicorn", Technology: "Gunicorn", VersionToken: "gunicorn"},
		{Keyword: "uvicorn", Technology: "Uvicorn", VersionToken: "uvicorn"},
	},
	"x-powered-by": {
		{Keyword: "express", Technology: "Express.js"},
		{Keyword: "django", Technology: "Django"},
		{Keyword: "asp.net", Technology: "ASP.NET", VersionToken: "asp.net"},
		{Keyword: "php", Technology: "PHP", VersionToken: "php"},
		{Keyword: "laravel", Technology: "Laravel"},
		{Keyword: "rails", Technology: "Ruby on Rails"},
		{Keyword: "flask", Technology: "Flask"},
		{Keyword: "spring", Technology: "Spring Framework"},
	},
	"x-generator": {
		{Keyword: "drupal", Technology: "Drupal", VersionToken: "drupal"},
		{Keyword: "wordpress", Technology: "WordPress", VersionToken: "wordpress"},
	},
}

// directTechnologyHeaders name a technology by being present at all.
var directTechnologyHeaders = map[string]modules.DirectHeader{
	"x-aspnet-version":    {Technology: "ASP.NET", ValueIsVersion: true},
	"x-aspnetmvc-version": {Technology: "ASP.NET MVC", ValueIsVersion: true},
	"x-drupal-cache":      {Technology: "Drupal"},
	"x-mod-pagespeed":     {Technology: "Google PageSpeed", ValueIsVersion: true},
	"x-varnish":           {Technology: "Varnish Cache"},
	"x-runtime":           {Technology: "Dynamic Runtime", ValueIsVersion: true},
}
