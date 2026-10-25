package HTTPSTest

// Verdict texts.
const (
	secureConnectionDescription = "Connection is secured with HTTPS protocol - data transmission is encrypted"

	insecureConnectionDescription = "Connection uses insecure HTTP protocol - data is transmitted in plaintext " +
		"and vulnerable to interception"

	unknownAddressDescription = "Unable to verify HTTPS - the address the page was served from is unavailable"
)
