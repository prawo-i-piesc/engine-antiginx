package UnitTests

import (
	"Engine-AntiGinx/App/SSRF"
	"Engine-AntiGinx/App/SiteTests"
	"Engine-AntiGinx/App/SiteTests/SSLCertificateSecurityTest"
	"Engine-AntiGinx/App/SiteTests/UnitTestKit"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The certificates in testdata/ are test-only fixtures; none of them is used anywhere else.
// ca.pem is a fixture root that signs most of the others, intermediate.pem is a CA under it
// that signs chained.pem, and self_signed.pem and expired_self_signed.pem are signed by
// their own keys. expired.pem expired inside the root's own validity window, so its chain
// still validates at a moment when it was valid. They live in a
// testdata directory so the secret scanner in CI (Trivy, which skips test paths) does not
// take the fixture private keys for leaked ones; testdata/.gitignore lets *.pem be committed.
//
// The test verifies the presented certificate against the system trust store. On Linux that
// store is read from SSL_CERT_FILE and SSL_CERT_DIR the first time it is needed, so TestMain
// points it at the fixture root alone, before any test runs. A certificate signed by the
// fixture root is then as trusted as a public one would be on a real scan, which is what makes
// the expiry, hostname, key-size and validity branches reachable. Where the platform ignores
// those variables (macOS, Windows) the trusted cases are skipped; the untrusted ones still run.
func TestMain(m *testing.M) {
	root, err := filepath.Abs(filepath.Join("testdata", "ca.pem"))
	if err == nil {
		_ = os.Setenv("SSL_CERT_FILE", root)
		_ = os.Setenv("SSL_CERT_DIR", filepath.Join(filepath.Dir(root), "no-system-roots"))
	}
	os.Exit(m.Run())
}

// readPEM returns the DER bytes of the first block of a PEM fixture.
func readPEM(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("reading %s: %v", name, err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatalf("%s holds no PEM block", name)
	}
	return block.Bytes
}

// loadPair loads testdata/<name>.pem with its key testdata/<name>-key.pem, followed by the named
// chain certificates the server should send after it.
func loadPair(t *testing.T, name string, chain ...string) tls.Certificate {
	t.Helper()
	pair, err := tls.LoadX509KeyPair(filepath.Join("testdata", name+".pem"), filepath.Join("testdata", name+"-key.pem"))
	if err != nil {
		t.Fatalf("loading certificate %s: %v", name, err)
	}
	for _, extra := range chain {
		pair.Certificate = append(pair.Certificate, readPEM(t, extra))
	}
	return pair
}

// serveTLS serves the certificate over HTTPS on a local address and returns the target URL.
func serveTLS(t *testing.T, certificate tls.Certificate) string {
	t.Helper()
	t.Setenv(SSRF.AllowPrivateEnv, "true")
	server := httptest.NewUnstartedServer(http.NotFoundHandler())
	server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server.URL
}

// requireTrustedRoot skips a test when the platform does not take its trust store from
// SSL_CERT_FILE, so the fixture root cannot stand in for a public CA.
func requireTrustedRoot(t *testing.T) {
	t.Helper()
	root, err := x509.ParseCertificate(readPEM(t, "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := root.Verify(x509.VerifyOptions{}); err != nil {
		t.Skipf("the fixture root is not trusted on this platform (%v)", err)
	}
}

func TestTrustedCertificates(t *testing.T) {
	cases := []struct {
		name      string
		cert      string
		chain     []string
		level     SiteTests.ThreatLevel
		fragments []string
	}{
		{"valid RSA", "valid", nil, SiteTests.None, []string{"valid, strong, and not expiring soon"}},
		{"valid ECDSA", "valid_ecdsa", nil, SiteTests.None, []string{"valid, strong, and not expiring soon"}},
		{"intermediate sent", "chained", []string{"intermediate.pem"}, SiteTests.None, []string{"valid, strong, and not expiring soon"}},
		{"intermediate missing", "chained", nil, SiteTests.Critical, []string{"Certificate chain validation failed", "unknown authority"}},
		{"hostname mismatch", "hostname_mismatch", nil, SiteTests.High, []string{"Certificate hostname mismatch", "127.0.0.1"}},
		{"expired", "expired", nil, SiteTests.High, []string{"Certificate has expired."}},
		{"not yet valid", "not_yet_valid", nil, SiteTests.High, []string{"Certificate is not yet valid."}},
		{"short RSA key", "short_rsa_key", nil, SiteTests.Medium, []string{"short RSA key (1024 bits)"}},
		// Signed by the trusted root, but with SHA-1, which no browser accepts any more
		{"SHA-1 signature", "sha1_signature", nil, SiteTests.Critical, []string{"insecure signature algorithm (SHA1-RSA) that browsers reject"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			requireTrustedRoot(t)
			target := serveTLS(t, loadPair(t, c.cert, c.chain...))
			result := UnitTestKit.RunTarget(t, SSLCertificateSecurityTest.New(), target)
			UnitTestKit.Expect(t, result, c.level, c.fragments...)
		})
	}
}

// A certificate about to expire cannot be committed, since it would only stay "about to
// expire" for a few weeks, so it is issued by the fixture root when the test runs.
func TestExpiringSoon(t *testing.T) {
	requireTrustedRoot(t)
	root, err := x509.ParseCertificate(readPEM(t, "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	rootKey, err := x509.ParsePKCS8PrivateKey(readPEM(t, "ca-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{Organization: []string{"AntiGinx Fixtures"}, CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(10 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, root, key.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}

	target := serveTLS(t, tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key})
	result := UnitTestKit.RunTarget(t, SSLCertificateSecurityTest.New(), target)
	UnitTestKit.Expect(t, result, SiteTests.Info, "will expire in less than 30 days")
}

// A certificate signed by its own key is not trusted by any store, so this case holds on
// every platform.
func TestSelfSignedIsCritical(t *testing.T) {
	target := serveTLS(t, loadPair(t, "self_signed"))
	result := UnitTestKit.RunTarget(t, SSLCertificateSecurityTest.New(), target)
	UnitTestKit.Expect(t, result, SiteTests.Critical, "Certificate chain validation failed")

	metadata := UnitTestKit.Metadata(t, result)
	want := map[string]any{
		"Subject":            "CN=localhost,O=AntiGinx Fixtures",
		"Issuer":             "CN=localhost,O=AntiGinx Fixtures",
		"SignatureAlgorithm": "SHA256-RSA",
		"PublicKeyType":      "RSA",
		"PublicKeyBits":      float64(2048),
		"IsCA":               false,
		"NotAfter":           "2126-01-01T00:00:00Z",
	}
	for field, value := range want {
		if metadata[field] != value {
			t.Errorf("metadata %s = %v, want %v", field, metadata[field], value)
		}
	}
	if names, _ := metadata["DNSNames"].([]any); len(names) != 1 || names[0] != "localhost" {
		t.Errorf("metadata DNSNames = %v, want [localhost]", metadata["DNSNames"])
	}
}

// The metadata describes the leaf the server presented, not the CA that signed it.
func TestMetadataDescribesPresentedCertificate(t *testing.T) {
	requireTrustedRoot(t)
	target := serveTLS(t, loadPair(t, "valid_ecdsa"))
	result := UnitTestKit.RunTarget(t, SSLCertificateSecurityTest.New(), target)

	metadata := UnitTestKit.Metadata(t, result)
	if metadata["Issuer"] != "CN=AntiGinx Fixture Root CA,O=AntiGinx Fixtures" || metadata["Subject"] != "CN=localhost,O=AntiGinx Fixtures" {
		t.Errorf("metadata names issuer %v and subject %v", metadata["Issuer"], metadata["Subject"])
	}
	if metadata["PublicKeyType"] != "ECDSA" || metadata["PublicKeyBits"] != float64(256) {
		t.Errorf("metadata describes key %v/%v, want ECDSA/256", metadata["PublicKeyType"], metadata["PublicKeyBits"])
	}
}

// An expired certificate nobody trusts is reported for the untrusted chain, the worse of
// its two problems, with the expiry mentioned alongside.
func TestExpiredAndUntrustedIsCritical(t *testing.T) {
	target := serveTLS(t, loadPair(t, "expired_self_signed"))
	result := UnitTestKit.RunTarget(t, SSLCertificateSecurityTest.New(), target)
	UnitTestKit.Expect(t, result, SiteTests.Critical, "Certificate chain validation failed", "unknown authority", "Certificate has expired.")
}

// A port that speaks plain HTTP never completes a TLS handshake.
func TestPlainHTTPPortIsCritical(t *testing.T) {
	site := UnitTestKit.ServeSite(t, t.TempDir())
	target := "https://" + site.Listener.Addr().String()

	result := UnitTestKit.RunTarget(t, SSLCertificateSecurityTest.New(), target)
	UnitTestKit.Expect(t, result, SiteTests.Critical, "Failed to establish TLS connection")
	if result.Metadata != nil {
		t.Errorf("failed connection carries metadata %v", result.Metadata)
	}
}

// Without the opt-out the dialer refuses a local address, which is reported as a failed
// connection rather than as a certificate problem.
func TestLocalTargetRefusedWithoutOptOut(t *testing.T) {
	target := serveTLS(t, loadPair(t, "self_signed"))
	t.Setenv(SSRF.AllowPrivateEnv, "")

	result := UnitTestKit.RunTarget(t, SSLCertificateSecurityTest.New(), target)
	UnitTestKit.Expect(t, result, SiteTests.Critical, "Failed to establish TLS connection", "not allowed")
}
