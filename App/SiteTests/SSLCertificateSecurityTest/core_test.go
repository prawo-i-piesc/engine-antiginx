package SSLCertificateSecurityTest

import (
	"Engine-AntiGinx/App/SiteTests"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"
)

// now is the moment every certificate in these tests is judged at.
var now = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

// authority is a throwaway CA the test trusts in place of the system store.
type authority struct {
	cert  *x509.Certificate
	key   crypto.Signer
	roots *x509.CertPool
}

func newAuthority(t *testing.T) authority {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Root"},
		NotBefore:             now.AddDate(-1, 0, 0),
		NotAfter:              now.AddDate(10, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	cert := create(t, template, template, key.Public(), key)
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	return authority{cert: cert, key: key, roots: roots}
}

// leaf describes the certificate a test wants the CA to issue.
type leaf struct {
	host      string
	notBefore time.Time
	notAfter  time.Time
	key       crypto.Signer
}

func (a authority) issue(t *testing.T, l leaf) *x509.Certificate {
	t.Helper()
	if l.key == nil {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		l.key = key
	}
	if l.notBefore.IsZero() {
		l.notBefore = now.AddDate(0, -1, 0)
	}
	if l.notAfter.IsZero() {
		l.notAfter = now.AddDate(1, 0, 0)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: l.host},
		DNSNames:     []string{l.host},
		NotBefore:    l.notBefore,
		NotAfter:     l.notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	return create(t, template, a.cert, l.key.Public(), a.key)
}

func create(t *testing.T, template, parent *x509.Certificate, public crypto.PublicKey, signer crypto.Signer) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, template, parent, public, signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestAssess(t *testing.T) {
	ca := newAuthority(t)
	shortRSA, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	shortECDSA, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name     string
		cert     *x509.Certificate
		host     string
		want     SiteTests.ThreatLevel
		contains string
	}{
		{"valid", ca.issue(t, leaf{host: "example.com"}), "example.com", SiteTests.None, "valid, strong, and not expiring soon"},
		{"expiring soon", ca.issue(t, leaf{host: "example.com", notAfter: now.AddDate(0, 0, 10)}), "example.com", SiteTests.Info, "expire in less than 30 days"},
		{"expired", ca.issue(t, leaf{host: "example.com", notBefore: now.AddDate(-2, 0, 0), notAfter: now.AddDate(0, 0, -1)}), "example.com", SiteTests.Medium, "has expired"},
		{"not yet valid", ca.issue(t, leaf{host: "example.com", notBefore: now.AddDate(0, 0, 1)}), "example.com", SiteTests.Medium, "not yet valid"},
		{"hostname mismatch", ca.issue(t, leaf{host: "other.com"}), "example.com", SiteTests.Medium, "hostname mismatch"},
		{"short RSA key", ca.issue(t, leaf{host: "example.com", key: shortRSA}), "example.com", SiteTests.Medium, "short RSA key (1024 bits)"},
		{"short ECDSA key", ca.issue(t, leaf{host: "example.com", key: shortECDSA}), "example.com", SiteTests.Medium, "short ECDSA key (224 bits)"},
	}
	for _, c := range cases {
		level, description := assess([]*x509.Certificate{c.cert}, c.host, ca.roots, now)
		if level != c.want || !strings.Contains(description, c.contains) {
			t.Errorf("%s: got %v %q, want %v mentioning %q", c.name, level, description, c.want, c.contains)
		}
	}
}

func TestAssessUntrustedChain(t *testing.T) {
	ca := newAuthority(t)
	cert := ca.issue(t, leaf{host: "example.com"})

	// The issuing CA is not in this trust store, as with a self-signed or private CA
	level, description := assess([]*x509.Certificate{cert}, "example.com", x509.NewCertPool(), now)
	if level != SiteTests.Medium || !strings.Contains(description, "chain validation failed") {
		t.Errorf("untrusted chain gave %v %q, want Medium", level, description)
	}
}

func TestDescribeCertificate(t *testing.T) {
	ca := newAuthority(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	info := describeCertificate(ca.issue(t, leaf{host: "example.com", key: key}))
	if info.PublicKeyType != "RSA" || info.PublicKeyBits != 2048 || info.Issuer != "CN=Test Root" || info.DNSNames[0] != "example.com" {
		t.Errorf("certificate described as %+v", info)
	}

	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(describeCertificate(ca.issue(t, leaf{host: "example.com", key: edKey})))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"PublicKeyType":"Unknown"`) || strings.Contains(string(encoded), "PublicKeyBits") {
		t.Errorf("unsized key type serialized as %s, want Unknown and no bit count", encoded)
	}
}
