// Package SSLCertificateSecurityTest implements the SSL Certificate Security Analysis security test.
// See README.md for what it checks, how it grades and what it reports.
package SSLCertificateSecurityTest

import (
	"Engine-AntiGinx/App/SSRF"
	"Engine-AntiGinx/App/SiteTests"
	"bytes"
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

			conn, err := tls.DialWithDialer(SSRF.NewDialer(10*time.Second), "tcp", address, &tls.Config{
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

				// An expired or not yet valid leaf is rejected before its chain is even
				// built, so verify it again at a moment inside its validity window: only a
				// chain that would then validate makes the expiry the whole story.
				var certInvalidErr x509.CertificateInvalidError
				expiryNote := ""
				if errors.As(verifyErr, &certInvalidErr) && certInvalidErr.Reason == x509.Expired {
					description := "Certificate has expired."
					if time.Now().Before(cert.NotBefore) {
						description = "Certificate is not yet valid."
					}
					insideWindow := opts
					insideWindow.DNSName = ""
					insideWindow.CurrentTime = cert.NotBefore.Add(cert.NotAfter.Sub(cert.NotBefore) / 2)
					_, windowErr := cert.Verify(insideWindow)
					if windowErr == nil {
						return SiteTests.TestResult{
							Name:        TestName,
							Certainty:   100,
							ThreatLevel: SiteTests.High,
							Metadata:    metadata,
							Description: description,
						}
					}
					verifyErr = windowErr
					expiryNote = " " + description
				}

				// Go refuses MD5 and SHA-1 signatures outright, as browsers do; the
				// resulting error only names an unknown authority, so ask for it directly.
				if algorithm, insecure := insecureSignature(verifyErr, certs); insecure {
					return SiteTests.TestResult{
						Name:        TestName,
						Certainty:   100,
						ThreatLevel: SiteTests.Critical,
						Metadata:    metadata,
						Description: fmt.Sprintf("Certificate uses an insecure signature algorithm (%s) that browsers reject, so the chain cannot be validated.%s", algorithm, expiryNote),
					}
				}

				// Self-signed, untrusted root, or other chain validation failure.
				return SiteTests.TestResult{
					Name:        TestName,
					Certainty:   100,
					ThreatLevel: SiteTests.Critical,
					Metadata:    metadata,
					Description: "Certificate chain validation failed: " + verifyErr.Error() + "." + expiryNote,
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

// insecureAlgorithms are the signature algorithms Go's verifier rejects with an
// x509.InsecureAlgorithmError, as browsers do: every MD2, MD5 and SHA-1 based one.
var insecureAlgorithms = map[x509.SignatureAlgorithm]bool{
	x509.MD2WithRSA:    true,
	x509.MD5WithRSA:    true,
	x509.SHA1WithRSA:   true,
	x509.DSAWithSHA1:   true,
	x509.ECDSAWithSHA1: true,
}

// insecureSignature reports whether verification failed because a certificate in the
// presented chain is signed with an insecure algorithm, and names it. The verifier reports
// that only as a hint inside an UnknownAuthorityError, which cannot be unwrapped, so the
// presented certificates are checked directly. Self-signed certificates are skipped, since
// nothing checks a root's signature over itself.
func insecureSignature(verifyErr error, certs []*x509.Certificate) (x509.SignatureAlgorithm, bool) {
	var insecureErr x509.InsecureAlgorithmError
	if errors.As(verifyErr, &insecureErr) {
		return x509.SignatureAlgorithm(insecureErr), true
	}
	for _, cert := range certs {
		if !bytes.Equal(cert.RawIssuer, cert.RawSubject) && insecureAlgorithms[cert.SignatureAlgorithm] {
			return cert.SignatureAlgorithm, true
		}
	}
	return x509.UnknownSignatureAlgorithm, false
}
