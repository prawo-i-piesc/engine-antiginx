// Package SSLCertificateSecurityTest implements the SSL Certificate Security Analysis security test.
// See README.md for what it checks, how it grades and what it reports.
package SSLCertificateSecurityTest

import (
	"Engine-AntiGinx/App/SiteTests"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"time"
)

// New creates a new StructureTest that analyzes the SSL/TLS certificate of the target website
// for security best practices.
func New() *SiteTests.StructureTest {
	return &SiteTests.StructureTest{
		Id:          TestId,
		Name:        TestName,
		Description: TestDescription,
		Category:    TestCategory,
		RunTest: func(params SiteTests.StructureTestParams) SiteTests.TestResult {
			url := params.Target
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
				return SiteTests.TestResult{
					Name:        TestName,
					Certainty:   100,
					ThreatLevel: SiteTests.Critical,
					Metadata:    nil,
					Description: "Failed to establish TLS connection: " + err.Error(),
				}
			}
			defer func() {
				if err := conn.Close(); err != nil {
					fmt.Printf("SSLCertTest \nWarning: Failed to close connection channel: %s", err.Error())
				}
			}()
			state := conn.ConnectionState()
			tlsState := &state

			certs := tlsState.PeerCertificates

			if len(certs) == 0 {
				return SiteTests.TestResult{
					Name:        TestName,
					Certainty:   100,
					ThreatLevel: SiteTests.Critical,
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
					return SiteTests.TestResult{
						Name:        TestName,
						Certainty:   100,
						ThreatLevel: SiteTests.High,
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
						return SiteTests.TestResult{
							Name:        TestName,
							Certainty:   100,
							ThreatLevel: SiteTests.High,
							Metadata:    metadata,
							Description: description,
						}
					}
				}

				// Self-signed, untrusted root, or other chain validation failure.
				return SiteTests.TestResult{
					Name:        TestName,
					Certainty:   100,
					ThreatLevel: SiteTests.Critical,
					Metadata:    metadata,
					Description: "Certificate chain validation failed: " + verifyErr.Error(),
				}
			}

			now := time.Now()
			// Check for hostname mismatch
			if err := cert.VerifyHostname(host); err != nil {
				return SiteTests.TestResult{
					Name:        TestName,
					Certainty:   100,
					ThreatLevel: SiteTests.High,
					Metadata:    metadata,
					Description: "Certificate hostname mismatch: " + err.Error(),
				}
			}

			// Check for self-signed certificate
			if cert.Issuer.String() == cert.Subject.String() {
				return SiteTests.TestResult{
					Name:        TestName,
					Certainty:   100,
					ThreatLevel: SiteTests.Critical,
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
				return SiteTests.TestResult{
					Name:        TestName,
					Certainty:   100,
					ThreatLevel: SiteTests.Critical,
					Metadata:    metadata,
					Description: "Certificate chain verification failed: " + err.Error(),
				}
			}

			// Check for weak signature algorithms
			if cert.SignatureAlgorithm.String() == "MD5-RSA" || cert.SignatureAlgorithm.String() == "SHA1-RSA" {
				return SiteTests.TestResult{
					Name:        TestName,
					Certainty:   100,
					ThreatLevel: SiteTests.Medium,
					Metadata:    metadata,
					Description: "Certificate uses a weak signature algorithm (MD5 or SHA1).",
				}
			}

			// Check for short public key length
			switch pubKey := cert.PublicKey.(type) {
			case *rsa.PublicKey:
				if pubKey.N.BitLen() < 2048 {
					return SiteTests.TestResult{
						Name:        TestName,
						Certainty:   100,
						ThreatLevel: SiteTests.Medium,
						Metadata:    metadata,
						Description: fmt.Sprintf("Certificate uses a short RSA key (%d bits). Minimum recommended is 2048 bits.", pubKey.N.BitLen()),
					}
				}
			case *ecdsa.PublicKey:
				if pubKey.Curve.Params().BitSize < 256 {
					return SiteTests.TestResult{
						Name:        TestName,
						Certainty:   100,
						ThreatLevel: SiteTests.Medium,
						Metadata:    metadata,
						Description: fmt.Sprintf("Certificate uses a short ECDSA key (%d bits). Minimum recommended is 256 bits.", pubKey.Curve.Params().BitSize),
					}
				}
			}

			daysLeft := int(cert.NotAfter.Sub(now).Hours() / 24)
			if daysLeft < 30 {
				return SiteTests.TestResult{
					Name:        TestName,
					Certainty:   100,
					ThreatLevel: SiteTests.Info,
					Metadata:    metadata,
					Description: "Certificate is valid but will expire in less than 30 days.",
				}
			}

			return SiteTests.TestResult{
				Name:        TestName,
				Certainty:   100,
				ThreatLevel: SiteTests.None,
				Metadata:    metadata,
				Description: "SSL certificate is valid, strong, and not expiring soon.",
			}
		},
	}
}
