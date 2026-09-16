package FaviconOriginTest

// Identity of the test.
const (
	TestId          = "favicon-origin"
	TestName        = "Favicon Origin Analysis"
	TestDescription = "Checks whether the page loads its favicon from another domain, especially from the domain of a brand it may be impersonating"
	TestCategory    = "Phishing"
)

// Confidence in the verdict.
const (
	faviconFactCertainty  = 100 // Where an icon is loaded from is read straight from the page
	faviconBrandCertainty = 85  // The brand may run the page under a domain the dataset does not list
	faviconUnreadable     = 50  // The page or its address could not be read
)

// maxScannedBody caps how much of the page is searched for icon declarations, which live in
// the head and therefore near the start of any sane document.
const maxScannedBody = 1024 * 1024
