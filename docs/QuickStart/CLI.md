# 💻 Quick Start — CLI
This guide shows you how to run Engine-AntiGinx locally from your terminal.

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

#### 📌 Binary Name Note
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



## 🛡️ Valid Test IDs (`--tests`)
| Test ID | Description |
|---|---|
| `https` | HTTPS Protocol Verification |
| `hsts` | HSTS Header Analysis |
| `serv-h-a` | Server Header Analysis + security context |
| `csp` | Content Security Policy |
| `cookie-sec` | Cookie Security |
| `js-obf` | JavaScript Obfuscation Detection |
| `xframe` | Clickjacking Protection |
| `permissions-policy` | Browser Permission Control |
| `x-content-type-options` | MIME Sniffing Protection |
| `referrer-policy` | Referrer Policy |
| `ssl-cert` | SSL/TLS Certificate Security |
| `cross-origin-x` | Cross-Origin Security Headers |

#### ⚠️ Important
- Use these IDs exactly. Typos or old aliases will result in parser errors.

<br>

## 📝 Usage Examples

#### Single Test
```bash
go run ./App/main.go test --target https://example.com --tests https 
```

<br>

#### Multiple Tests + Anti-Bot
```bash
go run ./App/main.go test --target example.com --tests https hsts csp xframe --antiBotDetection
```

<br>

#### Custom User-Agent
```bash
go run ./App/main.go test --target example.com --tests serv-h-a ssl-cert --userAgent "MyScanner/2.0"
```

<br>

## 📄 JSON File Mode

#### Example `scan.json`

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

<br>

#### Run `scan.json`:
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

<br>

Prints general usage or detailed info about available tests and parameters.
```bash
go run ./App/main.go help --tests
```

<br>

## 🔧 Troubleshooting
- **Error: invalid worker param** → Verify the command is `test`, `json`, `rawjson`, or `help`.
- **Parser argument errors** → Ensure `--target` and `--tests` have valid values.
- **No results / HTTP errors** → Check host availability, DNS, certificate, and any WAF/anti-bot protection.
