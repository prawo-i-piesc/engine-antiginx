// Package SSLCertificateSecurityTest implements the SSL Certificate Security Analysis security test.
// See README.md for what it checks, how it grades and what it reports.
package SSLCertificateSecurityTest

import (
	"Engine-AntiGinx/App/SSRF"
	"Engine-AntiGinx/App/SiteTests"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"time"
)

// CertificateInfo describes the leaf certificate the server presented, reported as the
// result's metadata. Fields are in the alphabetical order of their JSON names, the order the
// metadata map this replaced was serialized in, so reports keep the same shape.
type CertificateInfo struct {
	DNSNames           []string      `json:"DNSNames"`
	IsCA               bool          `json:"IsCA"`
	Issuer             string        `json:"Issuer"`
	KeyUsage           x509.KeyUsage `json:"KeyUsage"`
	NotAfter           time.Time     `json:"NotAfter"`
	NotBefore          time.Time     `json:"NotBefore"`
	PublicKeyBits      int           `json:"PublicKeyBits,omitempty"` // Absent for a key type the test does not size
	PublicKeyType      string        `json:"PublicKeyType"`
	SignatureAlgorithm string        `json:"SignatureAlgorithm"`
	Subject            string        `json:"Subject"`
}

// New creates a new StructureTest that analyzes the SSL/TLS certificate of the target website
// for security best practices.
func New() *SiteTests.StructureTest {
	return &SiteTests.StructureTest{
		Id:          TestId,
		Name:        TestName,
		Description: TestDescription,
		Category:    TestCategory,
		RunTest: func(params SiteTests.StructureTestParams) SiteTests.TestResult {
			certs, err := fetchCertificates(params.Target)
			if err != nil {
				return result(SiteTests.Critical, nil, "Failed to establish TLS connection: "+err.Error())
			}
			if len(certs) == 0 {
				return result(SiteTests.Critical, nil, "No SSL certificate presented by the server.")
			}

			// nil roots verifies against the system trust store
			level, description := assess(certs, params.Target.Hostname(), nil, time.Now())
			return result(level, describeCertificate(certs[0]), description)
		},
	}
}

// result assembles a verdict. Every check is a fact about the certificate, so it is reported
// with full certainty.
func result(level SiteTests.ThreatLevel, metadata any, description string) SiteTests.TestResult {
	return SiteTests.TestResult{
		Name:        TestName,
		Certainty:   Certainty,
		ThreatLevel: level,
		Metadata:    metadata,
		Description: description,
	}
}

// fetchCertificates opens a TLS connection to the target, without verifying it so that a
// broken certificate can still be inspected, and returns the chain the server presented.
func fetchCertificates(target *url.URL) ([]*x509.Certificate, error) {
	port := target.Port()
	if port == "" {
		port = "443"
	}

	conn, err := tls.DialWithDialer(SSRF.NewDialer(dialTimeout), "tcp", net.JoinHostPort(target.Hostname(), port), &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := conn.Close(); err != nil {
			fmt.Printf("HttpClient \nWarning: Failed to close response channel: %s", err.Error())
		}
	}()
	return conn.ConnectionState().PeerCertificates, nil
}

// describeCertificate collects what the report shows about the leaf certificate.
func describeCertificate(cert *x509.Certificate) *CertificateInfo {
	info := &CertificateInfo{
		DNSNames:           cert.DNSNames,
		IsCA:               cert.IsCA,
		Issuer:             cert.Issuer.String(),
		KeyUsage:           cert.KeyUsage,
		NotAfter:           cert.NotAfter,
		NotBefore:          cert.NotBefore,
		PublicKeyType:      "Unknown",
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		Subject:            cert.Subject.String(),
	}
	switch pubKey := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		info.PublicKeyType = "RSA"
		info.PublicKeyBits = pubKey.N.BitLen()
	case *ecdsa.PublicKey:
		info.PublicKeyType = "ECDSA"
		info.PublicKeyBits = pubKey.Curve.Params().BitSize
	}
	return info
}

// assess grades a presented chain for the host it was served for, checking the most serious
// problems first and stopping at the first one found. roots is the trust store, nil for the
// system's; now is the moment validity is judged at.
func assess(certs []*x509.Certificate, host string, roots *x509.CertPool, now time.Time) (SiteTests.ThreatLevel, string) {
	cert := certs[0]

	// Build intermediates pool from the certificate chain provided by the server.
	intermediates := x509.NewCertPool()
	for _, c := range certs[1:] {
		intermediates.AddCert(c)
	}

	// Perform explicit x509 verification using the hostname from the request URL
	// so that self-signed, invalid-chain, and hostname-mismatch cases are detected.
	_, verifyErr := cert.Verify(x509.VerifyOptions{
		DNSName:       host,
		Intermediates: intermediates,
		Roots:         roots,
		CurrentTime:   now,
	})
	if verifyErr != nil {
		var hostnameErr x509.HostnameError
		if errors.As(verifyErr, &hostnameErr) {
			return SiteTests.High, "Certificate hostname mismatch: " + verifyErr.Error()
		}

		var certInvalidErr x509.CertificateInvalidError
		if errors.As(verifyErr, &certInvalidErr) && certInvalidErr.Reason == x509.Expired {
			if now.Before(cert.NotBefore) {
				return SiteTests.High, "Certificate is not yet valid."
			}
			return SiteTests.High, "Certificate has expired."
		}

		// Self-signed, untrusted root, or other chain validation failure.
		return SiteTests.Critical, "Certificate chain validation failed: " + verifyErr.Error()
	}

	// Check for hostname mismatch
	if err := cert.VerifyHostname(host); err != nil {
		return SiteTests.High, "Certificate hostname mismatch: " + err.Error()
	}

	// Check for self-signed certificate
	if cert.Issuer.String() == cert.Subject.String() {
		return SiteTests.Critical, "Certificate is self-signed."
	}

	// Check certificate chain completeness.
	if _, err := cert.Verify(x509.VerifyOptions{Intermediates: intermediates, Roots: roots, CurrentTime: now}); err != nil {
		return SiteTests.Critical, "Certificate chain verification failed: " + err.Error()
	}

	// Check for weak signature algorithms
	if cert.SignatureAlgorithm == x509.MD5WithRSA || cert.SignatureAlgorithm == x509.SHA1WithRSA {
		return SiteTests.Medium, "Certificate uses a weak signature algorithm (MD5 or SHA1)."
	}

	// Check for short public key length
	switch pubKey := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		if bits := pubKey.N.BitLen(); bits < minRSAKeyBits {
			return SiteTests.Medium, fmt.Sprintf("Certificate uses a short RSA key (%d bits). Minimum recommended is %d bits.", bits, minRSAKeyBits)
		}
	case *ecdsa.PublicKey:
		if bits := pubKey.Curve.Params().BitSize; bits < minECDSAKeyBits {
			return SiteTests.Medium, fmt.Sprintf("Certificate uses a short ECDSA key (%d bits). Minimum recommended is %d bits.", bits, minECDSAKeyBits)
		}
	}

	if cert.NotAfter.Sub(now) < expiryWarning {
		return SiteTests.Info, "Certificate is valid but will expire in less than 30 days."
	}

	return SiteTests.None, "SSL certificate is valid, strong, and not expiring soon."
}
