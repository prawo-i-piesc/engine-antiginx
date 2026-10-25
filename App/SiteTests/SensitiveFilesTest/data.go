package SensitiveFilesTest

import (
	"Engine-AntiGinx/App/SiteTests"
	"Engine-AntiGinx/App/SiteTests/SensitivePaths"
)

// categorySeverity maps each shared category to the severity this test reports when a file
// in it is openly readable. Severity is this test's judgement and lives here, not in the
// shared list: a readable credential or repository is as bad as exposure gets, a dumped
// database or backup archive nearly so, server-information endpoints and logs are serious,
// and a dependency manifest or editor file is minor on its own.
var categorySeverity = map[string]SiteTests.ThreatLevel{
	SensitivePaths.CategoryCredentials:    SiteTests.Critical,
	SensitivePaths.CategoryVersionControl: SiteTests.Critical,
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
