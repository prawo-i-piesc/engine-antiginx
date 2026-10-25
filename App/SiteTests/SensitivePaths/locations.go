package SensitivePaths

// Locations are path fragments naming places that were never meant to be found: admin
// panels, APIs and their docs, configuration, development and backup areas, private and
// temporary storage. Unlike Files they are not requested — a fragment such as /admin is
// only a finding when a site itself points at it, so SitemapSecurityTest and
// RobotsTxtSecurityTest match the paths a sitemap or robots.txt declares against it.
// Fragments are lowercase, like the paths they are compared with.
var Locations = map[string]string{
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
