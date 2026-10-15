package SSRF

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestValidateHostBlocks(t *testing.T) {
	for _, h := range []string{
		"169.254.169.254", "127.0.0.1", "10.0.0.5", "192.168.1.1", "172.16.0.1", "0.0.0.0",
		"100.64.0.1", "[::1]", "::1", "fd00::1", "::ffff:127.0.0.1", "fe80::1", "64:ff9b::7f00:1",
		"localhost", "rabbitmq", "postgres.data.svc", "db.cluster.local", "printer.local",
		"2130706433", "0x7f.0.0.1", "127.1", "localhost.",
	} {
		if err := ValidateHost(h); err == nil {
			t.Errorf("%q should be blocked", h)
		}
	}
}

func TestValidateHostAllows(t *testing.T) {
	for _, h := range []string{"example.com", "sub.example.co.uk", "8.8.8.8", "2606:4700::1111", "abc.def.com"} {
		if err := ValidateHost(h); err != nil {
			t.Errorf("%q should be allowed: %v", h, err)
		}
	}
}

func TestValidateURLScheme(t *testing.T) {
	u, _ := url.Parse("file:///etc/passwd")
	if ValidateURL(u) == nil {
		t.Error("file scheme must be blocked")
	}
}

func TestDialerBlocksLoopbackServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	if _, err := NewClient(2 * time.Second).Get(srv.URL); err == nil {
		t.Fatal("request to loopback must fail")
	}
	t.Setenv(AllowPrivateEnv, "true")
	resp, err := NewClient(2 * time.Second).Get(srv.URL)
	if err != nil {
		t.Fatalf("override should allow: %v", err)
	}
	_ = resp.Body.Close()
}

func TestRedirectToMetadataBlocked(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://169.254.169.254/", nil)
	if CheckRedirect(req, nil) == nil {
		t.Error("redirect to metadata must be blocked")
	}
}
