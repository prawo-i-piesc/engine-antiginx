package SitemapSecurityTest

// dangerousPatterns are the path fragments whose presence in a sitemap means the site is
// actively inviting search engines to index something that was never meant to be found.
var dangerousPatterns = map[string]string{
	// Administrative Interfaces
	`/admin`:         "Administrative Interface",
	`/administrator`: "Administrative Interface",
	`/wp-admin`:      "Administrative Interface",
	`/phpmyadmin`:    "Administrative Interface",
	`/cpanel`:        "Administrative Interface",
	`/manager`:       "Administrative Interface",
	`/console`:       "Administrative Interface",
	`/panel`:         "Administrative Interface",
	`/dashboard`:     "Administrative Interface",
	`/control`:       "Administrative Interface",

	// API Endpoints
	`/api`:      "API Endpoint",
	`/rest`:     "API Endpoint",
	`/graphql`:  "API Endpoint",
	`/v1`:       "API Endpoint",
	`/v2`:       "API Endpoint",
	`/v3`:       "API Endpoint",
	`/swagger`:  "API Documentation",
	`/api-docs`: "API Documentation",
	`/openapi`:  "API Documentation",
	`/docs/api`: "API Documentation",

	// Configuration & Environment
	`/.env`:          "Configuration File",
	`/config`:        "Configuration File",
	`/.git`:          "Version Control",
	`/.svn`:          "Version Control",
	`/settings`:      "Configuration File",
	`/configuration`: "Configuration File",
	`/env`:           "Configuration File",

	// Development & Testing
	`/debug`:       "Development Path",
	`/test`:        "Development Path",
	`/testing`:     "Development Path",
	`/dev`:         "Development Path",
	`/development`: "Development Path",
	`/staging`:     "Development Path",
	`/qa`:          "Development Path",
	`/uat`:         "Development Path",

	// Backup & Sensitive Files
	`/backup`:   "Backup Location",
	`/backups`:  "Backup Location",
	`/.backup`:  "Backup Location",
	`/dump`:     "Database Dump",
	`/sql`:      "Database Dump",
	`/database`: "Database Dump",
	`/db`:       "Database Dump",

	// Internal & Private
	`/private`:  "Private Area",
	`/internal`: "Internal Area",
	`/hidden`:   "Private Area",
	`/temp`:     "Temporary Files",
	`/tmp`:      "Temporary Files",
	`/cache`:    "Cache Files",
	`/logs`:     "Log Files",
	`/log`:      "Log Files",
}
