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
- Signature algorithm, rejecting MD5 and SHA-1.
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
4. Check the leaf's signature algorithm, key type and key length, and how long it has left.

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
| **Medium** | Weak signature algorithm or short key |
| **High** | Expired, not yet valid, or hostname mismatch |
| **Critical** | No certificate, self-signed, or a chain that does not validate |

## Files

| File | Holds |
|---|---|
| `config.go` | What tunes it: identity constants, thresholds and confidence levels. |
| `core.go` | The test itself: `New()`, the orchestration and the assembled verdict. |

## Notes

The handshake deliberately skips verification so that an invalid certificate can be inspected and reported rather than causing the connection to fail with nothing to say. Verification is then performed explicitly against the retrieved chain.

---

The framework this test plugs into, and the conventions every test folder follows, are documented in [`App/SiteTests/Types.go`](../Types.go).
