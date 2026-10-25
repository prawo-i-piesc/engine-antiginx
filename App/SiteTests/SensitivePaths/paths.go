// Package SensitivePaths is the one list of files that should never be reachable on a
// public web server: secrets, credentials, version-control directories, database dumps,
// backups, server-information endpoints, logs and development artefacts.
//
// It is data, not a test: it declares no New() and is not registered. Three tests read it —
// SitemapSecurityTest and RobotsTxtSecurityTest flag any of these paths a sitemap or
// robots.txt declares, and SensitiveFilesTest requests each of them from the server. Keeping
// the list in one place means a file added here is looked for by all of them at once. Each
// entry carries only its path and a category; how severe a match is belongs to the test that
// found it, so no severity lives here.
//
// Alongside the files it holds Locations, the dangerous path fragments the sitemap and
// robots.txt tests share, and the Matcher both of them match declared paths with.
package SensitivePaths

import "strings"

// File is one sensitive file, named by the path it is requested at.
type File struct {
	Path     string // request path, leading slash, case preserved (e.g. /.git/config)
	Category string // what kind of exposure it is, reported as-is
}

// AsPatterns returns the list as a lowercased path-to-category map, the form the sitemap and
// robots.txt tests match declared paths against. Lowercasing happens here, once, because
// those tests compare against a lowercased path; SensitiveFilesTest requests the paths with
// their case preserved and so reads File.Path directly instead.
func AsPatterns() map[string]string {
	patterns := make(map[string]string, len(Files))
	for _, file := range Files {
		patterns[strings.ToLower(file.Path)] = file.Category
	}
	return patterns
}

// Categories used across the list, so a test maps a category to a severity in one place.
const (
	CategorySecrets        = "Secrets & Configuration"
	CategoryCredentials    = "Credentials"
	CategoryVersionControl = "Version Control"
	CategoryDatabaseDump   = "Database Dump"
	CategoryBackup         = "Backup"
	CategoryServerInfo     = "Server Information"
	CategoryLog            = "Log File"
	CategoryDevArtifact    = "Development Artifact"
)

// Files is the unified list. It is deliberately a starter set of high-signal paths rather
// than an exhaustive wordlist: every entry here is a file whose mere presence on a public
// server is a finding, not one that merely might be interesting.
var Files = []File{
	// Secrets & configuration — environment files and backup copies of config that keep
	// their secrets in plain text while no longer being interpreted by the application.
	{"/.env", CategorySecrets},
	{"/.env.local", CategorySecrets},
	{"/.env.dev", CategorySecrets},
	{"/.env.prod", CategorySecrets},
	{"/.env.production", CategorySecrets},
	{"/.env.backup", CategorySecrets},
	{"/.env.bak", CategorySecrets},
	{"/.env.save", CategorySecrets},
	{"/config.php.bak", CategorySecrets},
	{"/config.php~", CategorySecrets},
	{"/config.php.save", CategorySecrets},
	{"/wp-config.php.bak", CategorySecrets},
	{"/wp-config.php~", CategorySecrets},
	{"/wp-config.php.save", CategorySecrets},
	{"/web.config.bak", CategorySecrets},
	{"/settings.py.bak", CategorySecrets},
	{"/application.properties", CategorySecrets},
	{"/appsettings.json", CategorySecrets},

	// Credentials — key material and password files.
	{"/.htpasswd", CategoryCredentials},
	{"/.netrc", CategoryCredentials},
	{"/.pgpass", CategoryCredentials},
	{"/.aws/credentials", CategoryCredentials},
	{"/.ssh/id_rsa", CategoryCredentials},
	{"/id_rsa", CategoryCredentials},
	{"/id_dsa", CategoryCredentials},
	{"/.git-credentials", CategoryCredentials},
	{"/secrets.yml", CategoryCredentials},
	{"/credentials.json", CategoryCredentials},

	// Version control — a reachable repository lets the whole source tree be reconstructed.
	{"/.git/config", CategoryVersionControl},
	{"/.git/HEAD", CategoryVersionControl},
	{"/.git/index", CategoryVersionControl},
	{"/.git/logs/HEAD", CategoryVersionControl},
	{"/.svn/entries", CategoryVersionControl},
	{"/.svn/wc.db", CategoryVersionControl},
	{"/.hg/store/00manifest.i", CategoryVersionControl},
	{"/.bzr/branch/last-revision", CategoryVersionControl},

	// Database dumps.
	{"/dump.sql", CategoryDatabaseDump},
	{"/database.sql", CategoryDatabaseDump},
	{"/db.sql", CategoryDatabaseDump},
	{"/backup.sql", CategoryDatabaseDump},
	{"/mysql.sql", CategoryDatabaseDump},
	{"/data.sql", CategoryDatabaseDump},

	// Archive backups of the site or its code.
	{"/backup.zip", CategoryBackup},
	{"/backup.tar.gz", CategoryBackup},
	{"/backup.tar", CategoryBackup},
	{"/backup.rar", CategoryBackup},
	{"/www.zip", CategoryBackup},
	{"/site.zip", CategoryBackup},
	{"/public_html.zip", CategoryBackup},
	{"/index.php.bak", CategoryBackup},
	{"/index.html.bak", CategoryBackup},

	// Server information — endpoints that disclose configuration or internal state.
	{"/phpinfo.php", CategoryServerInfo},
	{"/info.php", CategoryServerInfo},
	{"/test.php", CategoryServerInfo},
	{"/server-status", CategoryServerInfo},
	{"/server-info", CategoryServerInfo},
	{"/actuator", CategoryServerInfo},
	{"/actuator/env", CategoryServerInfo},
	{"/actuator/health", CategoryServerInfo},
	{"/metrics", CategoryServerInfo},

	// Logs.
	{"/error.log", CategoryLog},
	{"/errors.log", CategoryLog},
	{"/debug.log", CategoryLog},
	{"/access.log", CategoryLog},
	{"/php_errors.log", CategoryLog},
	{"/laravel.log", CategoryLog},
	{"/storage/logs/laravel.log", CategoryLog},
	{"/npm-debug.log", CategoryLog},

	// Development artefacts — dependency manifests, container and CI files, editor state.
	{"/.DS_Store", CategoryDevArtifact},
	{"/composer.json", CategoryDevArtifact},
	{"/composer.lock", CategoryDevArtifact},
	{"/package.json", CategoryDevArtifact},
	{"/package-lock.json", CategoryDevArtifact},
	{"/yarn.lock", CategoryDevArtifact},
	{"/.npmrc", CategoryDevArtifact},
	{"/Dockerfile", CategoryDevArtifact},
	{"/docker-compose.yml", CategoryDevArtifact},
	{"/.dockerignore", CategoryDevArtifact},
	{"/Gemfile", CategoryDevArtifact},
	{"/.gitlab-ci.yml", CategoryDevArtifact},
	{"/.travis.yml", CategoryDevArtifact},
	{"/phpunit.xml", CategoryDevArtifact},
	{"/webpack.config.js", CategoryDevArtifact},
	{"/.vscode/settings.json", CategoryDevArtifact},
	{"/.idea/workspace.xml", CategoryDevArtifact},
}
