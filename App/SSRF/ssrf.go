// Package SSRF keeps the scanner from being used to reach the infrastructure it runs in.
// A scan target is user input, so it is checked twice: by name before anything is requested,
// and by resolved address at connection time, which also covers redirects and DNS rebinding.
package SSRF

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"syscall"
	"time"
)

// AllowPrivateEnv names the environment variable that disables the protection. It exists for
// local development and tests against servers on localhost and must not be set in production.
const AllowPrivateEnv = "ANTIGINX_ALLOW_PRIVATE_TARGETS"

// ErrBlocked is wrapped by every error produced when a target is refused.
var ErrBlocked = errors.New("target is not allowed: it points to a private or internal address")

// blockedPrefixes are address ranges that are not publicly routable, beyond what the
// standard library classifies as private, loopback or link-local.
var blockedPrefixes = mustPrefixes(
	"0.0.0.0/8",       // "this" network
	"100.64.0.0/10",   // carrier-grade NAT, also used for some cloud metadata
	"192.0.0.0/24",    // IETF protocol assignments
	"192.0.2.0/24",    // TEST-NET-1
	"198.18.0.0/15",   // benchmarking
	"198.51.100.0/24", // TEST-NET-2
	"203.0.113.0/24",  // TEST-NET-3
	"240.0.0.0/4",     // reserved, includes broadcast
	"64:ff9b::/96",    // NAT64, embeds an IPv4 address
	"100::/64",        // discard-only
	"2001:db8::/32",   // documentation
)

// internalSuffixes are names that only resolve inside a cluster or a private network.
var internalSuffixes = []string{
	".local", ".localhost", ".internal", ".intranet", ".lan", ".home", ".corp", ".private",
	".localdomain", ".svc", ".cluster.local", ".consul", ".docker",
}

func mustPrefixes(cidrs ...string) []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, len(cidrs))
	for _, cidr := range cidrs {
		prefixes = append(prefixes, netip.MustParsePrefix(cidr))
	}
	return prefixes
}

func disabled() bool {
	return os.Getenv(AllowPrivateEnv) == "true"
}

// IsBlockedIP reports whether an address must never be contacted.
func IsBlockedIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || ip.IsUnspecified() || ip.IsLoopback() || ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() ||
		ip.IsMulticast() {
		return true
	}
	for _, prefix := range blockedPrefixes {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

// ValidateHost refuses names that are internal by construction: literal private addresses,
// localhost, single-label names such as "rabbitmq" and cluster or private-network suffixes.
func ValidateHost(host string) error {
	if disabled() {
		return nil
	}
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" {
		return fmt.Errorf("%w: empty host", ErrBlocked)
	}
	if addr, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		if IsBlockedIP(addr) {
			return fmt.Errorf("%w: %s", ErrBlocked, host)
		}
		return nil
	}
	// Numeric forms such as 2130706433 or 0x7f.1 are interpreted as IPv4 by resolvers.
	if looksNumeric(host) {
		return fmt.Errorf("%w: %s", ErrBlocked, host)
	}
	if host == "localhost" || !strings.Contains(host, ".") {
		return fmt.Errorf("%w: %s", ErrBlocked, host)
	}
	for _, suffix := range internalSuffixes {
		if strings.HasSuffix(host, suffix) {
			return fmt.Errorf("%w: %s", ErrBlocked, host)
		}
	}
	return nil
}

// looksNumeric reports whether every label is a decimal or hexadecimal number, which no real
// public hostname is, but which inet_aton-style resolvers turn into an address.
func looksNumeric(host string) bool {
	for _, label := range strings.Split(host, ".") {
		label = strings.TrimPrefix(label, "0x")
		if label == "" {
			return false
		}
		for _, c := range label {
			if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') {
				return false
			}
		}
	}
	// A hex-looking label like "abc" would be a valid name, so require a digit-only or 0x form.
	for _, label := range strings.Split(host, ".") {
		if strings.HasPrefix(label, "0x") {
			continue
		}
		for _, c := range label {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}

// ValidateURL refuses a target whose scheme is not http(s) or whose host is internal.
func ValidateURL(target *url.URL) error {
	if target == nil {
		return fmt.Errorf("%w: no target", ErrBlocked)
	}
	if target.Scheme != "" && target.Scheme != "http" && target.Scheme != "https" {
		return fmt.Errorf("%w: unsupported scheme %q", ErrBlocked, target.Scheme)
	}
	return ValidateHost(target.Hostname())
}

// control is the net.Dialer hook that runs after name resolution, immediately before the
// socket connects, so it sees the address that will really be used.
func control(network, address string, _ syscall.RawConn) error {
	if disabled() {
		return nil
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrBlocked, err)
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || IsBlockedIP(addr) {
		return fmt.Errorf("%w: %s", ErrBlocked, host)
	}
	return nil
}

// NewDialer returns a dialer that refuses to connect to non-public addresses.
func NewDialer(timeout time.Duration) *net.Dialer {
	return &net.Dialer{Timeout: timeout, Control: control}
}

// DialContext dials through the protected dialer; use it as http.Transport.DialContext.
func DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return NewDialer(30*time.Second).DialContext(ctx, network, address)
}

// CheckRedirect validates every redirect hop by name; connection-time checks cover the rest.
func CheckRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return errors.New("stopped after 10 redirects")
	}
	return ValidateURL(req.URL)
}

// NewTransport returns an http.Transport that cannot reach non-public addresses and ignores
// proxy environment variables, which would otherwise bypass the dialer.
func NewTransport() *http.Transport {
	return &http.Transport{DialContext: DialContext}
}

// NewClient returns an http.Client protected against SSRF, including through redirects.
func NewClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, Transport: NewTransport(), CheckRedirect: CheckRedirect}
}
