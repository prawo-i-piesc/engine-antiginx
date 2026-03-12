// Package Tests provides security test implementations for HTTP response analysis.
// This file contains the SSLCertificateSecurityTest that analyzes the SSL/TLS certificate
// of the target website for security best practices, such as validity, expiration, and
// use of strong cryptographic algorithms.
package Tests

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
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
			tlsState := params.Response.TLS
			if tlsState == nil {
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
				state := conn.ConnectionState()
				tlsState = &state
			}

			certs := tlsState.PeerCertificates

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
				"Issuer":             cert.Issuer.String(),
				"Subject":            cert.Subject.String(),
				"NotBefore":          cert.NotBefore,
				"NotAfter":           cert.NotAfter,
				"SignatureAlgorithm": cert.SignatureAlgorithm.String(),
				"KeyUsage":           cert.KeyUsage,
				"DNSNames":           cert.DNSNames,
				"IsCA":               cert.IsCA,
			}

			// Populate public key metadata
			switch pubKey := cert.PublicKey.(type) {
			case *rsa.PublicKey:
				metadata["PublicKeyType"] = "RSA"
				metadata["PublicKeyBits"] = pubKey.N.BitLen()
			case *ecdsa.PublicKey:
				metadata["PublicKeyType"] = "ECDSA"
				metadata["PublicKeyBits"] = pubKey.Curve.Params().BitSize
			default:
				metadata["PublicKeyType"] = "Unknown"
			}

			// Build intermediates pool from the certificate chain provided by the server.
			intermediates := x509.NewCertPool()
			for _, c := range certs[1:] {
				intermediates.AddCert(c)
			}

			// Perform explicit x509 verification using the hostname from the request URL
			// so that self-signed, invalid-chain, and hostname-mismatch cases are detected.
			opts := x509.VerifyOptions{
				DNSName:       url.Hostname(),
				Intermediates: intermediates,
				CurrentTime:   time.Now(),
			}
			_, verifyErr := cert.Verify(opts)

			if verifyErr != nil {
				var hostnameErr x509.HostnameError
				if errors.As(verifyErr, &hostnameErr) {
					return TestResult{
						Name:        "SSL Certificate Security Analysis",
						Certainty:   100,
						ThreatLevel: High,
						Metadata:    metadata,
						Description: "Certificate hostname mismatch: " + verifyErr.Error(),
					}
				}

				var certInvalidErr x509.CertificateInvalidError
				if errors.As(verifyErr, &certInvalidErr) {
					switch certInvalidErr.Reason {
					case x509.Expired:
						description := "Certificate has expired."
						if time.Now().Before(cert.NotBefore) {
							description = "Certificate is not yet valid."
						}
						return TestResult{
							Name:        "SSL Certificate Security Analysis",
							Certainty:   100,
							ThreatLevel: High,
							Metadata:    metadata,
							Description: description,
						}
					}
				}

				// Self-signed, untrusted root, or other chain validation failure.
				return TestResult{
					Name:        "SSL Certificate Security Analysis",
					Certainty:   100,
					ThreatLevel: Critical,
					Metadata:    metadata,
					Description: "Certificate chain validation failed: " + verifyErr.Error(),
				}
			}

			now := time.Now()
			// Check for hostname mismatch
			if err := cert.VerifyHostname(host); err != nil {
				return TestResult{
					Name:        "SSL Certificate Security Analysis",
					Certainty:   100,
					ThreatLevel: High,
					Metadata:    metadata,
					Description: "Certificate hostname mismatch: " + err.Error(),
				}
			}

			// Check for self-signed certificate
			if cert.Issuer.String() == cert.Subject.String() {
				return TestResult{
					Name:        "SSL Certificate Security Analysis",
					Certainty:   100,
					ThreatLevel: Critical,
					Metadata:    metadata,
					Description: "Certificate is self-signed.",
				}
			}

			// Check certificate chain completeness.
			intermediatePool := x509.NewCertPool()
			for _, c := range certs[1:] {
				intermediatePool.AddCert(c)
			}
			if _, err := cert.Verify(x509.VerifyOptions{Intermediates: intermediatePool}); err != nil {
				return TestResult{
					Name:        "SSL Certificate Security Analysis",
					Certainty:   100,
					ThreatLevel: Critical,
					Metadata:    metadata,
					Description: "Certificate chain verification failed: " + err.Error(),
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

			// Check for short public key length
			switch pubKey := cert.PublicKey.(type) {
			case *rsa.PublicKey:
				if pubKey.N.BitLen() < 2048 {
					return TestResult{
						Name:        "SSL Certificate Security Analysis",
						Certainty:   100,
						ThreatLevel: Medium,
						Metadata:    metadata,
						Description: fmt.Sprintf("Certificate uses a short RSA key (%d bits). Minimum recommended is 2048 bits.", pubKey.N.BitLen()),
					}
				}
			case *ecdsa.PublicKey:
				if pubKey.Curve.Params().BitSize < 256 {
					return TestResult{
						Name:        "SSL Certificate Security Analysis",
						Certainty:   100,
						ThreatLevel: Medium,
						Metadata:    metadata,
						Description: fmt.Sprintf("Certificate uses a short ECDSA key (%d bits). Minimum recommended is 256 bits.", pubKey.Curve.Params().BitSize),
					}
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
