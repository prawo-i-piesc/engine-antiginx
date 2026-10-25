package SensitiveFilesTest

import (
	"Engine-AntiGinx/App/SiteTests"
	"Engine-AntiGinx/App/SiteTests/SensitivePaths"
)

// categorySeverity maps each shared category to the severity this test reports when a file
// in it is openly readable. Severity is this test's judgement and lives here, not in the
// shared list. Readable credentials, repositories, secrets, dumps and backups disclose
// confidential data (CVSS 3.1 C:H, about 7.5; ZAP rates "Source Code Disclosure - Git" High),
// server-information endpoints and logs disclose internals (Medium), and a dependency
// manifest or editor file is minor on its own (Low). Critical is left to CVEs rated Critical.
var categorySeverity = map[string]SiteTests.ThreatLevel{
	SensitivePaths.CategoryCredentials:    SiteTests.High,
	SensitivePaths.CategoryVersionControl: SiteTests.High,
	SensitivePaths.CategorySecrets:        SiteTests.High,
	SensitivePaths.CategoryDatabaseDump:   SiteTests.High,
	SensitivePaths.CategoryBackup:         SiteTests.High,
	SensitivePaths.CategoryServerInfo:     SiteTests.Medium,
	SensitivePaths.CategoryLog:            SiteTests.Medium,
	SensitivePaths.CategoryDevArtifact:    SiteTests.Low,
}

// severityFor returns the severity for a category, defaulting to Low for anything unmapped.
func severityFor(category string) SiteTests.ThreatLevel {
	if severity, ok := categorySeverity[category]; ok {
		return severity
	}
	return SiteTests.Low
}
