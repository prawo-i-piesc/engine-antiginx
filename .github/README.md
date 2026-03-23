# ⚙️ Engine-AntiGinx
A lightweight, fast, and scalable **Security testing engine** built with Go. Designed to identify vulnerabilities, security misconfigurations, and compliance issues across web applications with surgical precision.

**Two deployment modes**: Standalone CLI for quick scans, or distributed worker for high-volume enterprise scanning via RabbitMQ message queue.


## 🌟 About the Project
**Engine-AntiGinx** is a modern security assessment tool that transforms how organizations discover and remediate web application vulnerabilities. It combines:

- **Concurrent scanning** — Tests run in parallel using goroutines for maximum speed
- **CVSS-aligned threat levels** — Easy-to-understand risk classification for stakeholders  
- **CVE cross-referencing** — Automatic NIST NVD vulnerability database lookups
- **Zero-config deployment** — Works standalone or integrates seamlessly with your infrastructure
- **API-ready output** — JSON results for easy integration with SIEM, ticketing, and CI/CD systems

**Core architecture:**
- **App** — Fast CLI scanner for manual scans and test orchestration
- **Engined** — Background daemon for high-throughput, queue-driven scanning



## 💻 Technologies
| Technology | Purpose | Details |
|---|---|---|
| 🎯 **Go 1.25** | Core language | Concurrent, compiled, production-ready |
| 🐰 **RabbitMQ** | Task queue | Scale scanning to multiple workers |
| 🐳 **Docker** | Containers | Multi-arch builds (amd64/arm64) |
| 🐙 **Docker Compose** | Orchestration | One-command deployment with full stack |
| 🔄 **GitHub Actions** | CI/CD | Automated builds, tests, releases |
| 📦 **GHCR** | Registry | Pre-built images, always fresh |
| 📚 **MkDocs** | Docs | Material theme, fast search, GitHub Pages |



## ⚡ Key Features
- **🔍 Comprehensive Security Testing** — 12+ configurable security tests covering modern OWASP top concerns
- **⏱ High Performance** — Concurrent test execution with goroutines, minimal resource footprint
- **🔗 Queue-Driven Architecture** — RabbitMQ integration for distributed, high-throughput scanning
- **🎯 Structured Results** — CVSS severity levels, CVE identification, JSON output for integrations
- **🚀 Easy Deployment** — Standalone CLI or containerized with Docker/Docker Compose
- **📊 Enterprise-Ready** — Support for custom User-Agents, anti-bot detection, task tracking



## 📁 Project Structure
```
Engine-AntiGinx/
├── App/                      # CLI Security Scanner
│   ├── main.go               # App entry point
│   ├── CVE/                  # CVE vulnerability assessment (NIST NVD)
│   ├── Errors/               # Structured error handling
│   ├── Helpers/              # Utility functions (math, strings, formatting)
│   ├── HTTP/                 # HTTP client with anti-bot detection
│   ├── parser/               # CLI argument parser with validation
│   ├── Registry/             # Thread-safe test registry
│   ├── Reporter/             # Results reporter (CLI/Backend modes)
│   ├── Runner/               # Job orchestrator
│   ├── execution/            # Execution plan & formatter system
│   └── Tests/                # Security test implementations (12 tests)
├── Engined/                  # Background Daemon
│   ├── main.go               # RabbitMQ consumer entry point
│   └── queueconfig.go        # Queue configuration
├── docs/                     # MkDocs documentation
│   ├── EngineAntiginx/       # Project overview
│   └── QuickStart/           # Installation & usage guides
├── docker-compose.yml        # Container orchestration
├── Dockerfile                # Multi-stage Docker build
├── mkdocs.yml                # Documentation configuration
├── go.mod                    # Go module dependencies
├── go.sum                    # Dependency lock
├── LICENSE                   # Apache 2.0 License
└── .env.example              # Environment template
```



## 🔧 Security Tests Available
| Test ID | Name | Description | CVSS Focus |
|---|---|---|---|
| `https` | HTTPS Protocol Verification | Checks encrypted connection usage | Encryption |
| `hsts` | HSTS Header Analysis | HTTP Strict Transport Security config | Transport |
| `serv-h-a` | Server Header Analysis | Technology detection + CVE assessment | Information Disclosure |
| `csp` | Content Security Policy | XSS and injection attack prevention | XSS/Injection |
| `cookie-sec` | Cookie Security | Session management & security attributes | Session Mgmt |
| `js-obf` | JavaScript Obfuscation | Detects obfuscated code anomalies | Malware/APT |
| `xframe` | X-Frame-Options | Clickjacking protection validation | Clickjacking |
| `permissions-policy` | Permissions Policy | Browser feature access control | Feature Policy |
| `x-content-type-options` | MIME Sniffing Protection | MIME type enforcement | MIME Sniffing |
| `referrer-policy` | Referrer Policy | Privacy leak prevention via referrer | Privacy |
| `ssl-cert` | SSL/TLS Certificate Security | Certificate validity & strength | Encryption |
| `cross-origin-x` | Cross-Origin Security | COEP/CORP/COOP headers | Cross-Origin |



## 📋 Prerequisites
| Component | Version | Purpose |
|---|---|---|
| Go | 1.25+ | Build & run locally |
| Docker | 24+ | Containerization |
| Docker Compose | 2.0+ | Orchestration |
| RabbitMQ | 3.8+ | Task queue (optional) |



## 📚 Documentation
Our documentation is comprehensive and organized into logical sections:

- **[Quick Start](https://prawo-i-piesc.github.io/engine-antiginx/QuickStart/QuickStart/)** — Get running in minutes
  - [CLI Guide](https://prawo-i-piesc.github.io/engine-antiginx/QuickStart/CLI/) — All commands, parameters, examples
  - [Docker Guide](https://prawo-i-piesc.github.io/engine-antiginx/QuickStart/Docker/) — Container options & troubleshooting
  - [Docker Compose Guide](https://prawo-i-piesc.github.io/engine-antiginx/QuickStart/DockerCompose/) — Full example setup
- **[Engine-AntiGinx Overview](https://prawo-i-piesc.github.io/engine-antiginx/EngineAntiginx/EngineAntiginx/)** — Architecture & capabilities
- **[API Documentation](https://prawo-i-piesc.github.io/engine-antiginx/App/)** — Detailed package references



## Contributing
We welcome contributions! Please:
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Commit changes with clear messages
4. Push to the branch and create a Pull Request



## 📞 Support & Community
- 🐛 **Found a bug?** → [Open an Issue](https://github.com/prawo-i-piesc/engine-antiginx/issues)
- 💬 **Have a question?** → [Start a Discussion](https://github.com/prawo-i-piesc/engine-antiginx/discussions)
- 📧 **Commercial support** → Contact the Antiginx team



## 📄 Links
- 📦 [GitHub Repository](https://github.com/prawo-i-piesc/engine-antiginx)
- 🐳 [Container Images (GHCR)](https://github.com/prawo-i-piesc/engine-antiginx/pkgs/container/engine-antiginx)
- 📚 [Full Documentation (GitHub Pages)](https://prawo-i-piesc.github.io/engine-antiginx/)
- 🚀 [GitHub Actions & Releases](https://github.com/prawo-i-piesc/engine-antiginx/actions)
- 📝 [License](../LICENSE)
- 👥 [GitHub Team](https://github.com/prawo-i-piesc)



**Made with** ⚡ **for security professionals, developers, and DevOps teams worldwide.**