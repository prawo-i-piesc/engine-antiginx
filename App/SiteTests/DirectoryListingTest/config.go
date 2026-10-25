package DirectoryListingTest

import "time"

// Identity of the test.
const (
	TestId          = "dir-listing"
	TestName        = "Directory Listing Detection"
	TestDescription = "Probes the target and its common directories for server-generated directory listings"
	TestCategory    = "App-Configuration"
)

// Probe limits.
const (
	probeTimeout     = 10 * time.Second // Budget for one directory request, redirects included
	maxBodyBytes     = 256 * 1024       // Bytes of a response searched for a listing signature
	maxConcurrency   = 5                // Directories probed at the same time
	maxSampleEntries = 10               // Listed entries copied into the metadata per directory
)

// escalationCount is how many listings it takes for the verdict to be raised a level: one
// open directory can be an oversight, several mean listing is enabled server-wide.
const escalationCount = 3

// Certainty reported with every result.
const (
	listingFoundCertainty = 95 // A server signature matched; only a page mimicking one fools it
	noListingCertainty    = 80 // Only the common directories were probed, not every directory
)
