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
// for security best practices. Levels follow Nessus: a certificate that cannot be trusted for
// any reason (untrusted chain, expiry, hostname) is Medium, as plugin 51192 rates it, and so
// is a port without TLS, which leaves the site as exposed as an HTTP-only one; an MD5 or
// SHA-1 signature is High, as plugin 35291 rates it.
func New() *SiteTests.StructureTest {
	return &SiteTests.StructureTest{
		Id:          TestId,
		Name:        TestName,
		Description: TestDescription,
		Category:    TestCategory,
		RunTest: func(params SiteTests.StructureTestParams) SiteTests.TestResult {
			certs, err := fetchCertificates(params.Target)
			if err != nil {
				return result(SiteTests.Medium, nil, "Failed to establish TLS connection: "+err.Error())
			}
			if len(certs) == 0 {
				return result(SiteTests.Medium, nil, "No SSL certificate presented by the server.")
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
//
// A certificate browsers will not trust leaves visitors a warning to click through, which is
// what Nessus rates Medium ("SSL Certificate Cannot Be Trusted", 51192); a signature with an
// algorithm browsers reject is High (Nessus 35291, CVSS 3.1 7.5).
func assess(certs []*x509.Certificate, host string, roots *x509.CertPool, now time.Time) (SiteTests.ThreatLevel, string) {
	cert := certs[0]

	// Build intermediates pool from the certificate chain provided by the server.
	intermediates := x509.NewCertPool()
	for _, c := range certs[1:] {
		intermediates.AddCert(c)
	}

	// Perform explicit x509 verification using the hostname from the request URL
	// so that self-signed, invalid-chain, and hostname-mismatch cases are detected.
	opts := x509.VerifyOptions{
		DNSName:       host,
		Intermediates: intermediates,
		Roots:         roots,
		CurrentTime:   now,
	}
	_, verifyErr := cert.Verify(opts)
	if verifyErr != nil {
		var hostnameErr x509.HostnameError
		if errors.As(verifyErr, &hostnameErr) {
			return SiteTests.Medium, "Certificate hostname mismatch: " + verifyErr.Error()
		}

		// An expired or not yet valid leaf is rejected before its chain is even built, so
		// verify it again at a moment inside its validity window — the edge of the window
		// nearest to now, which the issuer's own validity covers in any sound chain: only a
		// chain that would then validate makes the expiry the whole story.
		var certInvalidErr x509.CertificateInvalidError
		expiryNote := ""
		if errors.As(verifyErr, &certInvalidErr) && certInvalidErr.Reason == x509.Expired {
			description := "Certificate has expired."
			insideWindow := opts
			insideWindow.DNSName = ""
			insideWindow.CurrentTime = cert.NotAfter.Add(-time.Second)
			if now.Before(cert.NotBefore) {
				description = "Certificate is not yet valid."
				insideWindow.CurrentTime = cert.NotBefore.Add(time.Second)
			}
			_, windowErr := cert.Verify(insideWindow)
			if windowErr == nil {
				return SiteTests.Medium, description
			}
			verifyErr = windowErr
			expiryNote = " " + description
		}

		// Go refuses MD5 and SHA-1 signatures outright, as browsers do; the resulting error
		// only names an unknown authority, so ask for it directly.
		if algorithm, insecure := insecureSignature(verifyErr, certs); insecure {
			return SiteTests.High, fmt.Sprintf("Certificate uses an insecure signature algorithm (%s) that browsers reject, so the chain cannot be validated.%s", algorithm, expiryNote)
		}

		// Self-signed, untrusted root, or other chain validation failure.
		return SiteTests.Medium, "Certificate chain validation failed: " + verifyErr.Error() + "." + expiryNote
	}

	// Check for hostname mismatch
	if err := cert.VerifyHostname(host); err != nil {
		return SiteTests.Medium, "Certificate hostname mismatch: " + err.Error()
	}

	// Check for self-signed certificate
	if cert.Issuer.String() == cert.Subject.String() {
		return SiteTests.Medium, "Certificate is self-signed."
	}

	// Check certificate chain completeness.
	if _, err := cert.Verify(x509.VerifyOptions{Intermediates: intermediates, Roots: roots, CurrentTime: now}); err != nil {
		return SiteTests.Medium, "Certificate chain verification failed: " + err.Error()
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
