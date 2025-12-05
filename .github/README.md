# ⚙️ Engine-AntiGinx

## About Project

Engine-AntiGinx is a security scanning tool designed to analyze websites and detect potential vulnerabilities and security misconfigurations. Built with Go, it performs concurrent security tests on web applications and reports findings with structured threat levels aligned with CVSS severity ratings.

The project consists of two main components:
- **App** - CLI security scanner for direct usage
- **Engined** - Background daemon that consumes tasks from RabbitMQ queue

## Technologies

| Technology            | Description                                               |
|-----------------------|-----------------------------------------------------------|
| 🎯 **Go 1.25**        | Main programming language                                 |
| 🐰 **RabbitMQ**       | Message queue for async task processing                   |
| 🐳 **Docker**         | Containerization with multi-arch build (amd64/arm64)      |
| 🐙 **Docker Compose** | Multi-container orchestration                             |
| 🔄 **GitHub Actions** | CI/CD: build, tests, release, documentation               |
| 📦 **GHCR**           | GitHub Container Registry for Docker images               |
| 📚 **MkDocs**         | Documentation with Material theme on GitHub Pages         |

## Project Structure

```
Engine-AntiGinx/
├── App/                      # CLI Security Scanner
│   ├── main.go               # App entry point
│   ├── CVE/                  # CVE vulnerability assessment (NIST NVD)
│   ├── Errors/               # Structured error handling
│   ├── Helpers/              # Utility functions
│   ├── HTTP/                 # HTTP client with anti-bot detection
│   ├── Parameter-Parser/     # CLI argument parser
│   ├── Registry/             # Test registry system
│   ├── Reporter/             # Results reporter (CLI/Backend)
│   ├── Runner/               # Job orchestrator
│   └── Tests/                # Security test implementations
├── Engined/                  # Background Daemon
│   └── main.go               # RabbitMQ consumer daemon
├── docs/                     # MkDocs documentation
├── docker-compose.yml        # Container orchestration
├── Dockerfile                # Multi-stage Docker build
├── mkdocs.yml                # Documentation configuration
├── go.mod                    # Go module dependencies
└── .env.example              # Environment variables template
```

### Core Components

#### App (CLI Scanner)
- **CVE** - Integration with NIST NVD API for CVE vulnerability assessment
- **Errors** - Structured error handling with error codes (100-499 ranges)
- **Helpers** - String utilities (case-insensitive search, deduplication)
- **HTTP** - HTTP client wrapper with anti-bot detection (Cloudflare, CAPTCHA)
- **Parameter-Parser** - CLI argument parser with validation and whitelist support
- **Registry** - Thread-safe test registry for managing security tests
- **Reporter** - Async results reporter (CLI output or HTTP backend)
- **Runner** - Job orchestrator using goroutines and fan-out pattern
- **Tests** - Security test implementations:
  - `https` - HTTPS protocol verification
  - `hsts` - HTTP Strict Transport Security analysis
  - `serv-h-a` - Server header information disclosure
  - `x-frame` - X-Frame-Options clickjacking protection

#### Engined (Daemon)
- RabbitMQ consumer listening on `scan_queue`
- Spawns App scanner for each incoming task
- Graceful shutdown on SIGINT
- ACK/NACK handling for message reliability

## Quick Start

### Prerequisites

- Go 1.25 or higher ([download here](https://go.dev/dl/))
- Docker & Docker Compose (optional)
- RabbitMQ (for Engined daemon)

### Running App Locally

```bash
# Clone the repository
git clone https://github.com/prawo-i-piesc/Engine-AntiGinx.git
cd Engine-AntiGinx

# Run security scan
go run ./App/main.go test --target example.com --tests https hsts serv-h-a
```

### Running with Docker Compose

```bash
# Copy and configure environment
cp .env.example .env
# Edit .env with your settings

# Build and run
docker compose up --build
```

### Environment Variables

| Variable                      | Description                    | Example                              |
|-------------------------------|--------------------------------|--------------------------------------|
| `RABBITMQ_URL`                | RabbitMQ connection string     | `amqp://guest:guest@localhost:5672/` |
| `BACK_URL`                    | Backend API URL for reporting  | `http://backend:3000/api/results`    |
| `ENGINE_ANTIGINX_DAEMON_PORT` | Engined exposed port           | `9090`                               |
| `ENGINE_ANTIGINX_APP_PORT`    | App exposed port               | `8080`                               |

### Using Pre-built Docker Image

```bash
# Pull the latest image
docker pull ghcr.io/prawo-i-piesc/engine-antiginx:latest

# Run the scanner
docker run ghcr.io/prawo-i-piesc/engine-antiginx:latest /engine-antiginx/App test --target example.com --tests https
```

## Available Security Tests

| Test ID     | Name                          | Description                                      |
|-------------|-------------------------------|--------------------------------------------------|
| `https`     | HTTPS Protocol Verification   | Checks if connection uses encrypted HTTPS        |
| `hsts`      | HSTS Header Analysis          | Analyzes HTTP Strict Transport Security config   |
| `serv-h-a`  | Server Header Analysis        | Detects technology disclosure + CVE assessment   |
| `x-frame`   | X-Frame-Options Check         | Validates clickjacking protection headers        |

## Links

- 📦 [GitHub Repository](https://github.com/prawo-i-piesc/engine-antiginx)
- 🐳 [Container Images (GHCR)](https://github.com/prawo-i-piesc/engine-antiginx/pkgs/container/engine-antiginx)
- 📚 [Documentation (GitHub Pages)](https://prawo-i-piesc.github.io/engine-antiginx/)
- 🚀 [GitHub Actions](https://github.com/prawo-i-piesc/engine-antiginx/actions)
- 📝 [License](../LICENSE)
