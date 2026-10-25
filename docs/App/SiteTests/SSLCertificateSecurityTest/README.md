# SSL Certificate Security Analysis

Opens its own TLS connection to the target and inspects the certificate it is presented with. The certificate is a property of how the target is configured rather than of any single request, which is why this test handshakes itself instead of reading the main response.

|  |  |
|---|---|
| **Test ID** | `ssl-cert` |
| **Phase** | Structure — opens its own connection to the target rather than reading the main response |
| **Category** | Encryption |

```bash
go run ./App/main.go test --target example.com --tests ssl-cert
```

## What it checks

- Chain validation against the system trust store, including intermediates the server sent.
- Hostname match between the certificate and the target.
- Validity window: expired, not yet valid, or expiring soon.
- Signature algorithm: a chain signed with MD5 or SHA-1 is rejected, as browsers reject it.
- Key strength: RSA below 2048 bits and ECDSA below 256 bits.
- Self-signed certificates and incomplete chains.

## How it works

1. Dial the target on its port, defaulting to 443, with a ten second timeout.
2. Handshake with verification **disabled**, deliberately: a certificate that fails
   validation is exactly the one worth reporting, and a verifying handshake would fail with
   nothing to inspect.
3. Verify explicitly against the retrieved chain and the system trust store, matching the
   hostname. The error type distinguishes a hostname mismatch from an expiry from a broken
   chain, and each is reported differently.
   - An expired or not yet valid leaf is rejected before its chain is built, so it is
     verified again at the midpoint of its validity window. Only when the chain validates
     then is the expiry reported on its own; otherwise the untrusted chain is reported and
     the expiry mentioned alongside.
   - Go's verifier refuses MD5 and SHA-1 signatures, but reports that only as a hint inside
     an "unknown authority" error. A failed verification is therefore checked for a
     presented certificate signed with one of those algorithms, and reported as an insecure
     signature algorithm (High) rather than as a generic chain failure.
4. Check the leaf's key type and key length, and how long it has left.

The checks are ordered by severity and return on the first hit, so a report names the worst
problem rather than the first one in file order.

## What it reports

| Field | Meaning |
|---|---|
| `Issuer` / `Subject` | Distinguished names from the leaf certificate |
| `NotBefore` / `NotAfter` | Its validity window |
| `SignatureAlgorithm` | How it was signed |
| `PublicKeyType` / `PublicKeyBits` | RSA or ECDSA, and the key size |
| `DNSNames` | The names it is valid for |
| `KeyUsage`, `IsCA` | Constraints declared on it |

## How the verdict is reached

| Level | When |
|---|---|
| **None** | Valid, strong, and not expiring soon |
| **Info** | Valid but expires within 30 days |
| **Medium** | No TLS connection (as exposed as an HTTP-only site); no certificate, self-signed, a chain that does not validate, expired, not yet valid, or hostname mismatch; or a short key |
| **High** | Signed with MD5 or SHA-1, which browsers reject |

An expired or not yet valid certificate whose chain would not validate inside its validity
window is reported for the untrusted chain, with the expiry mentioned alongside.

Calibrated to Nessus 51192 "SSL Certificate Cannot Be Trusted" (Medium) and 35291 "SSL Certificate Signed Using Weak Hashing Algorithm" (High), and OWASP ZAP 10106 for a site without HTTPS (Medium); see the [SiteTests overview](../README.md) for the severity scale.

## Files

| File | Holds |
|---|---|
| `config.go` | Identity constants, the handshake timeout, the key-size and expiry thresholds and the certainty. |
| `core.go` | The test itself: `New()`, the TLS handshake, the `CertificateInfo` it reports as metadata, and `assess`, which grades a chain against a trust store at a given moment. |
| `core_test.go` | Unit tests for every verdict, run against certificates issued by a throwaway CA the test trusts — no network involved. |

## Notes

The handshake deliberately skips verification so that an invalid certificate can be inspected and reported rather than causing the connection to fail with nothing to say. Verification is then performed explicitly against the retrieved chain.

---

The shared framework and test conventions are described in the [SiteTests overview](../README.md).
