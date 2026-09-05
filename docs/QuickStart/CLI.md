# 💻 Quick Start — CLI
This guide shows you how to run Engine-AntiGinx locally from your terminal.


<br>


## ✅ Requirements
- Go 1.25+ (for local CLI mode)
- Internet access (to scan targets)
- Optional: RabbitMQ (if integrating with `Engined`)


<br>


## ⚡ Quick Start
Start a quick scan in just one command:
```bash
go run ./App/main.go test --target example.com --tests https hsts serv-h-a
```


<br>


## 📖 Available Command Modes
| Mode | Description | Example |
|---|---|---|
| `test` | Manual parameter input via CLI | `go run ./App/main.go test --target example.com --tests https hsts` |
| `json` | Load config from JSON file | `go run ./App/main.go json ./scan.json` |
| `rawjson` | Load JSON from `stdin` | `cat scan.json \| go run ./App/main.go rawjson` |
| `help` | General or contextual help | `go run ./App/main.go help --tests` |

**📌 Binary Name Note:**

- Code examples may show `antiginx`, but it's safest to use `go run ./App/main.go ...` or your own compiled binary.


<br>


## ⚙️ Parameters for `test` Mode
| Parameter | Required | Arguments | Description |
|---|---|---|---|
| `--target` | ✅ Yes | 1 | Target host or URL (e.g., `example.com`, `https://example.com`) |
| `--tests` | ✅ Yes | multiple | List of test IDs to execute |
| `--userAgent` | ❌ No | 1 (default: `Scanner/1.0`) | Custom User-Agent header |
| `--antiBotDetection` | ❌ No | 0 (flag) | Enable anti-bot detection mechanisms |
| `--taskId` | depends on workflow | 1 | Task identifier (useful for backend/queue integrations) |


<br>


## 🛡️ Valid Test IDs (`--tests`)
| Test ID | Phase | Description | Details |
|---|---|---|---|
| `https` | Response | HTTPS Protocol Verification | [docs](https://github.com/prawo-i-piesc/engine-antiginx/blob/main/App/SiteTests/HTTPSTest/README.md) |
| `hsts` | Response | HSTS Header Analysis | [docs](https://github.com/prawo-i-piesc/engine-antiginx/blob/main/App/SiteTests/HSTSTest/README.md) |
| `serv-h-a` | Response | Server Header Analysis + security context | [docs](https://github.com/prawo-i-piesc/engine-antiginx/blob/main/App/SiteTests/ServerHeaderTest/README.md) |
| `csp` | Response | Content Security Policy | [docs](https://github.com/prawo-i-piesc/engine-antiginx/blob/main/App/SiteTests/CSPTest/README.md) |
| `cookie-sec` | Response | Cookie Security | [docs](https://github.com/prawo-i-piesc/engine-antiginx/blob/main/App/SiteTests/CookieSecurityTest/README.md) |
| `js-obf` | Response | JavaScript Obfuscation Detection | [docs](https://github.com/prawo-i-piesc/engine-antiginx/blob/main/App/SiteTests/JSObfuscationTest/README.md) |
| `xframe` | Response | Clickjacking Protection | [docs](https://github.com/prawo-i-piesc/engine-antiginx/blob/main/App/SiteTests/XFrameTest/README.md) |
| `permissions-policy` | Response | Browser Permission Control | [docs](https://github.com/prawo-i-piesc/engine-antiginx/blob/main/App/SiteTests/PermissionsPolicyTest/README.md) |
| `x-content-type-options` | Response | MIME Sniffing Protection | [docs](https://github.com/prawo-i-piesc/engine-antiginx/blob/main/App/SiteTests/XContentTypeOptionsTest/README.md) |
| `referrer-policy` | Response | Referrer Policy | [docs](https://github.com/prawo-i-piesc/engine-antiginx/blob/main/App/SiteTests/ReferrerPolicyTest/README.md) |
| `cross-origin-x` | Response | Cross-Origin Security Headers | [docs](https://github.com/prawo-i-piesc/engine-antiginx/blob/main/App/SiteTests/CrossOriginTest/README.md) |
| `phishing-url` | PreResponse | Typo-squatting, homograph and URL parameter analysis | [docs](https://github.com/prawo-i-piesc/engine-antiginx/blob/main/App/SiteTests/PhishingURLTest/README.md) |
| `bot-protection` | PreResponse | Bot protection / CDN / WAF layer in front of the target | [docs](https://github.com/prawo-i-piesc/engine-antiginx/blob/main/App/SiteTests/BotProtectionTest/README.md) |
| `ssl-cert` | Structure | SSL/TLS Certificate Security | [docs](https://github.com/prawo-i-piesc/engine-antiginx/blob/main/App/SiteTests/SSLCertificateSecurityTest/README.md) |
| `sitemap` | Structure | Dangerous paths exposed through sitemap.xml | [docs](https://github.com/prawo-i-piesc/engine-antiginx/blob/main/App/SiteTests/SitemapSecurityTest/README.md) |


<br>


## ⏱️ Execution Phases
Tests are grouped by the input they need, and the engine schedules each group separately.
You never select a phase — it follows from the test IDs you pass.

| Phase | Needs | Behaviour |
|---|---|---|
| **PreResponse** | The target URL only | Runs immediately, in parallel with the page fetch |
| **Response** | The fetched page — headers and body | The only phase that requires the request to succeed |
| **Structure** | The target's configuration | Opens its own connections (TLS handshake, sitemap fetch) |

Two consequences worth knowing:

- **A blocked target still gets scanned.** If the site sits behind a bot protection challenge,
  only the Response tests are skipped. The report says which ones, and the PreResponse and
  Structure findings are still there.
- **Structural scans skip the request.** `--tests ssl-cert sitemap` never fetches the page,
  because nothing in that selection needs it.


**⚠️ Important:**
- Use these IDs exactly. Typos or old aliases will result in parser errors.


<br>


## 📝 Usage Examples

### Single Test
```bash
go run ./App/main.go test --target https://example.com --tests https 
```

### Multiple Tests + Anti-Bot
```bash
go run ./App/main.go test --target example.com --tests https hsts csp xframe --antiBotDetection
```

### Custom User-Agent
```bash
go run ./App/main.go test --target example.com --tests serv-h-a ssl-cert --userAgent "MyScanner/2.0"
```


<br>


## 📄 JSON File Mode

### Example `scan.json`
```json
{
	"Target": "https://example.com",
	"Parameters": [
		{
			"Name": "--tests",
			"Arguments": ["https", "hsts", "csp"]
		},
		{
			"Name": "--antiBotDetection",
			"Arguments": []
		}
	]
}
```

### Run `scan.json`:
```bash
go run ./App/main.go json ./scan.json
```


<br>


## 🔀 Raw JSON Mode (stdin)
```bash
cat ./scan.json | go run ./App/main.go rawjson
```
Useful when input comes from another process, API, or message queue.


<br>


## 📚 Help Command
General help:
```bash
go run ./App/main.go help
```

Prints general usage or detailed info about available tests and parameters.
```bash
go run ./App/main.go help --tests
```


<br>


## 🔧 Troubleshooting
- **Error: invalid worker param** → Verify the command is `test`, `json`, `rawjson`, or `help`.
- **Parser argument errors** → Ensure `--target` and `--tests` have valid values.
- **No results / HTTP errors** → Check host availability, DNS, certificate, and any WAF/anti-bot protection.