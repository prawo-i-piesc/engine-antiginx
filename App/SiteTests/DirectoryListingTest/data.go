package DirectoryListingTest

import "Engine-AntiGinx/App/SiteTests/DirectoryListingTest/modules"

// commonDirectories are probed on every target. A listing here exposes what the site serves
// anyway, but also every file nobody linked to.
var commonDirectories = []string{
	"/",
	"/images/",
	"/img/",
	"/css/",
	"/js/",
	"/static/",
	"/assets/",
	"/media/",
	"/files/",
	"/public/",
	"/downloads/",
	"/docs/",
	"/vendor/",
	"/wp-content/",
	"/wp-content/plugins/",
	"/wp-includes/",
}

// sensitiveDirectories are probed as well, and a listing in one of them is graded higher:
// they hold uploads, backups, logs and code that were never meant to be browsed.
var sensitiveDirectories = []string{
	"/uploads/",
	"/upload/",
	"/wp-content/uploads/",
	"/backup/",
	"/backups/",
	"/logs/",
	"/log/",
	"/tmp/",
	"/temp/",
	"/data/",
	"/db/",
	"/sql/",
	"/includes/",
	"/inc/",
	"/config/",
	"/private/",
	"/admin/",
	"/old/",
	"/test/",
	"/storage/",
}

// listingSignatures are the markers the common servers put into a generated listing. Every
// marker of a signature must appear, compared case-insensitively, and the first signature that
// matches names the server, so the generic one comes last.
var listingSignatures = []modules.Signature{
	{Server: "Apache", Markers: []string{"<title>index of /", "<h1>index of /", "parent directory"}},
	{Server: "Apache", Markers: []string{"<title>index of /", "<h1>index of /", "?c=n;o=d"}},
	{Server: "nginx", Markers: []string{"<title>index of /", "<h1>index of /", `<a href="../">../</a>`}},
	{Server: "lighttpd", Markers: []string{"<title>index of /", `<div class="list">`}},
	{Server: "IIS", Markers: []string{"[to parent directory]"}},
	// An IIS root listing has no parent link; its directories are "<dir>" followed by the
	// link to them, which a page merely quoting dir output in a <pre> block does not have
	{Server: "IIS", Markers: []string{"<pre>", "&lt;dir&gt; <a href="}},
	{Server: "Tomcat", Markers: []string{"<title>directory listing for [/"}},
	{Server: "Jetty", Markers: []string{"<title>directory: /"}},
	{Server: "Python http.server", Markers: []string{"<title>directory listing for /"}},
	{Server: "Node serve", Markers: []string{"<title>files within /"}},
	{Server: "Generic", Markers: []string{"<title>index of /"}},
}
