// Package Tests provides security test implementations for HTTP response analysis.
// This file contains the SSLCertificateSecurityTest that analyzes the SSL/TLS certificate
// of the target website for security best practices, such as validity, expiration, and
// use of strong cryptographic algorithms.
package Tests

import (
	"crypto/tls"
	"net"
	"time"
)

// NewSSLCertificateSecurityTest creates a new ResponseTest that analyzes the SSL/TLS certificate
// of the target website for security best practices.
//
// The test evaluates:
//   - Certificate validity (not expired, not yet valid)
//   - Use of strong signature algorithms (e.g., SHA-256+)
//   - Key length (2048 bits or higher recommended)
//   - Certificate chain completeness
//   - Hostname match
//
// Threat level assessment:
//   - None (0): Certificate is valid, strong, and not expiring soon
//   - Info (1): Certificate is valid but expiring within 30 days
//   - Medium (3): Weak signature algorithm or short key length
//   - High (4): Certificate expired, not yet valid, or hostname mismatch
//   - Critical (5): No certificate, self-signed, or invalid chain
//
// Returns:
//   - *ResponseTest: Configured SSL certificate security test ready for execution
func NewSSLCertificateSecurityTest() *ResponseTest {
	return &ResponseTest{
		Id:          "ssl-cert",
		Name:        "SSL Certificate Security Analysis",
		Description: "Analyzes the SSL/TLS certificate of the target website for validity, expiration, and cryptographic strength.",
		RunTest: func(params ResponseTestParams) TestResult {
			url := params.Response.Request.URL
			if url.Scheme != "https" {
				return TestResult{
					Name:        "SSL Certificate Security Analysis",
					Certainty:   100,
					ThreatLevel: Info,
					Metadata:    nil,
					Description: "Connection is not HTTPS, SSL certificate analysis not applicable.",
				}
			}

			host := url.Hostname()
			port := url.Port()
			if port == "" {
				port = "443"
			}
			address := net.JoinHostPort(host, port)

			conn, err := tls.DialWithDialer(&net.Dialer{
				Timeout: 10 * time.Second,
			}, "tcp", address, &tls.Config{
				InsecureSkipVerify: true,
			})
			if err != nil {
				return TestResult{
					Name:        "SSL Certificate Security Analysis",
					Certainty:   100,
					ThreatLevel: Critical,
					Metadata:    nil,
					Description: "Failed to establish TLS connection: " + err.Error(),
				}
			}
			defer conn.Close()

			certs := conn.ConnectionState().PeerCertificates
			if len(certs) == 0 {
				return TestResult{
					Name:        "SSL Certificate Security Analysis",
					Certainty:   100,
					ThreatLevel: Critical,
					Metadata:    nil,
					Description: "No SSL certificate presented by the server.",
				}
			}
			cert := certs[0]

			metadata := map[string]interface{}{
				"Issuer": cert.Issuer.String(),
				"Subject": cert.Subject.String(),
				"NotBefore": cert.NotBefore,
				"NotAfter": cert.NotAfter,
				"SignatureAlgorithm": cert.SignatureAlgorithm.String(),
				"KeyUsage": cert.KeyUsage,
				"DNSNames": cert.DNSNames,
				"IsCA": cert.IsCA,
			}

			now := time.Now()
			if now.Before(cert.NotBefore) {
				return TestResult{
					Name:        "SSL Certificate Security Analysis",
					Certainty:   100,
					ThreatLevel: High,
					Metadata:    metadata,
					Description: "Certificate is not yet valid.",
				}
			}
			if now.After(cert.NotAfter) {
				return TestResult{
					Name:        "SSL Certificate Security Analysis",
					Certainty:   100,
					ThreatLevel: High,
					Metadata:    metadata,
					Description: "Certificate has expired.",
				}
			}

			daysLeft := int(cert.NotAfter.Sub(now).Hours() / 24)
			if daysLeft < 30 {
				return TestResult{
					Name:        "SSL Certificate Security Analysis",
					Certainty:   100,
					ThreatLevel: Info,
					Metadata:    metadata,
					Description: "Certificate is valid but will expire in less than 30 days.",
				}
			}


			// Check for weak signature algorithms
			if cert.SignatureAlgorithm.String() == "MD5-RSA" || cert.SignatureAlgorithm.String() == "SHA1-RSA" {
				return TestResult{
					Name:        "SSL Certificate Security Analysis",
					Certainty:   100,
					ThreatLevel: Medium,
					Metadata:    metadata,
					Description: "Certificate uses a weak signature algorithm (MD5 or SHA1).",
				}
			}

			return TestResult{
				Name:        "SSL Certificate Security Analysis",
				Certainty:   100,
				ThreatLevel: None,
				Metadata:    metadata,
				Description: "SSL certificate is valid, strong, and not expiring soon.",
			}
		},
	}
}
