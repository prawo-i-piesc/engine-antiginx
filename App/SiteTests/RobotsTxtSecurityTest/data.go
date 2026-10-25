package RobotsTxtSecurityTest

// extraPatterns extend SitemapSecurityTest.DangerousPatterns with what robots.txt files
// typically name: they are written to keep crawlers out of exactly these places, so they
// list login pages, installers, server internals and file types far more often than a
// sitemap does. An entry here wins over a sitemap entry with the same fragment.
var extraPatterns = map[string]string{
	// Authentication
	`/login`:          "Authentication Endpoint",
	`/signin`:         "Authentication Endpoint",
	`/wp-login`:       "Authentication Endpoint",
	`/auth`:           "Authentication Endpoint",
	`/oauth`:          "Authentication Endpoint",
	`/sso`:            "Authentication Endpoint",
	`/password`:       "Authentication Endpoint",
	`/reset-password`: "Authentication Endpoint",

	// Administrative Interfaces
	`/adminer`:     "Administrative Interface",
	`/pma`:         "Administrative Interface",
	`/webmail`:     "Administrative Interface",
	`/jenkins`:     "Administrative Interface",
	`/jmx-console`: "Administrative Interface",
	`/solr`:        "Administrative Interface",

	// Installation & Setup
	`/install`:   "Installation Script",
	`/installer`: "Installation Script",
	`/setup`:     "Installation Script",
	`/upgrade`:   "Installation Script",

	// Server Internals
	`/server-status`: "Server Internals",
	`/server-info`:   "Server Internals",
	`/phpinfo`:       "Server Internals",
	`/cgi-bin`:       "Server Internals",
	`/xmlrpc`:        "Server Internals",
	`/actuator`:      "Server Internals",
	`/metrics`:       "Server Internals",
	`/prometheus`:    "Server Internals",
	`/elmah`:         "Server Internals",
	`/trace`:         "Server Internals",

	// Configuration & Environment
	`/wp-config`:  "Configuration File",
	`/.htaccess`:  "Configuration File",
	`/.htpasswd`:  "Credentials",
	`/web.config`: "Configuration File",
	`/.npmrc`:     "Configuration File",
	`/.docker`:    "Configuration File",

	// Version Control
	`/.hg`:        "Version Control",
	`/.bzr`:       "Version Control",
	`/.ds_store`:  "Directory Metadata",
	`/.gitignore`: "Version Control",

	// Credentials & Keys
	`/.aws`:        "Credentials",
	`/.ssh`:        "Credentials",
	`/credentials`: "Credentials",
	`/secret`:      "Credentials",
	`/secrets`:     "Credentials",
	`/keys`:        "Credentials",

	// Uploads & Exports
	`/upload`:  "User Uploads",
	`/uploads`: "User Uploads",
	`/storage`: "User Uploads",
	`/export`:  "Data Export",
	`/exports`: "Data Export",

	// Sensitive file types, as robots.txt wildcards such as /*.sql$ name them
	`.sql`:    "Database Dump",
	`.sqlite`: "Database Dump",
	`.db`:     "Database Dump",
	`.bak`:    "Backup Location",
	`.old`:    "Backup Location",
	`.orig`:   "Backup Location",
	`.swp`:    "Backup Location",
	`.tar`:    "Backup Location",
	`.tgz`:    "Backup Location",
	`.log`:    "Log Files",
}
