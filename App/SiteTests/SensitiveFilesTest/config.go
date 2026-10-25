package SensitiveFilesTest

import "time"

// Identity of the test.
const (
	TestId          = "sensitive-files"
	TestName        = "Sensitive File Exposure"
	TestDescription = "Requests a list of known sensitive files (secrets, backups, repositories, dumps) directly from the server"
	TestCategory    = "App-Configuration"
)

// Probe limits.
const (
	probeTimeout     = 10 * time.Second // Budget for one file request, redirects included
	maxBodyBytes     = 64 * 1024        // Bytes of a response read to tell a hit from a soft 404
	maxConcurrency   = 8                // Files requested at the same time
	softMatchPercent = 5                // Body-length window, in %, within which a 200 is treated as a soft 404
)

// escalationCount is how many exposed files it takes to raise the verdict a level.
const escalationCount = 3

// Certainty reported with every result.
const (
	exposureFoundCertainty = 95 // A file answered as itself, not as the soft-404 page
	noExposureCertainty    = 80 // Only the known list was tried, not every possible file
)
