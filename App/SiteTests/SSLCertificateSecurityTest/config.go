package SSLCertificateSecurityTest

import "time"

// Identity of the test.
const (
	TestId          = "ssl-cert"
	TestName        = "SSL Certificate Security Analysis"
	TestDescription = "Analyzes the SSL/TLS certificate of the target website for validity, expiration, and cryptographic strength."
	TestCategory    = "Encryption"
)

// Certainty reported with every result; each check is a fact about the certificate.
const Certainty = 100

// dialTimeout bounds the TLS handshake with the target.
const dialTimeout = 10 * time.Second

// Strength and lifetime thresholds.
const (
	minRSAKeyBits   = 2048                // Shortest RSA key not reported as weak
	minECDSAKeyBits = 256                 // Shortest ECDSA key not reported as weak
	expiryWarning   = 30 * 24 * time.Hour // Remaining validity below which expiry is reported
)
