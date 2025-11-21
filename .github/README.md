# ⚙️ Engine-AntiGinx

## About Project

Engine-AntiGinx is a security scanning tool designed to analyze websites and detect potential vulnerabilities and bot protection mechanisms. Built with Go, it performs concurrent security tests on web applications and reports findings with structured threat levels.

## Technologies

| Technologies          | Description                                               |
|-----------------------|-----------------------------------------------------------|
| 🎯 **Go 1.25**        | Main programming language                                |
| 🐳 **Docker**         | Containerization with multi-stage build                  |
| 🔄 **GitHub Actions** | CI/CD: build, tests, release, auto-labeling              |
| 📦 **GHCR**           | GitHub Container Registry for Docker images              |
| 📚 **GitHub Pages**   | Documentation hosting                                    |

## Project Structure

```
Engine-AntiGinx/
├── App/
│   ├── Errors/          # Error handling structures
│   ├── Helpers/         # Utility functions
│   ├── HTTP/            # HTTP client wrapper
│   ├── Parameter-Parser/ # CLI argument parser
│   ├── Registry/        # Test registry system
│   ├── Reporter/        # Results reporter
│   ├── Runner/          # Job orchestrator
│   └── Tests/           # Security test implementations
├── docs/                # Documentation files
├── main.go              # Application entry point
├── go.mod               # Go module dependencies
└── Dockerfile           # Docker configuration
```

### Core Components

- **App/Errors** - Structured error handling with panic-based system and error codes for different failure scenarios
- **App/Helpers** - String manipulation utilities including case-insensitive substring search
- **App/HTTP** - HTTP client wrapper with bot protection detection (Cloudflare, CAPTCHA) and configurable headers
- **App/Parameter-Parser** - CLI argument parser with validation, whitelist support, and structured error reporting
- **App/Registry** - Thread-safe test registry for managing and retrieving available security tests
- **App/Reporter** - Asynchronous results reporter using Go channels (producer-consumer pattern)
- **App/Runner** - Main job orchestrator that coordinates tests execution using goroutines and WaitGroups
- **App/Tests** - Security test implementations with threat level classification (HTTPS verification, etc.)

## Quick Start

### Prerequisites

- Go 1.25 or higher ([download here](https://go.dev/dl/))
- Docker (optional)

### Running Locally

```bash
# Clone the repository
git clone https://github.com/prawo-i-piesc/Engine-AntiGinx.git
cd Engine-AntiGinx

# Run the scanner
go run main.go test --target example.com --tests https
```

### Using Docker

```bash
# Build the image
docker build -t engine-antiginx .

# Run the scanner
docker run engine-antiginx test --target example.com --tests https
```

### Using Pre-built Docker Image

```bash
# Pull the latest image
docker pull ghcr.io/prawo-i-piesc/engine-antiginx:latest

# Run the scanner
docker run ghcr.io/prawo-i-piesc/engine-antiginx:latest test --target example.com --tests https
```

## Links

- 📦 [GitHub Repository](https://github.com/prawo-i-piesc/engine-antiginx)
- 🐳 [Container Images (GHCR)](https://github.com/prawo-i-piesc/engine-antiginx/pkgs/container/engine-antiginx)
- 📚 [Documentation (GitHub Pages)](https://prawo-i-piesc.github.io/engine-antiginx/)
- 🚀 [GitHub Actions](https://github.com/prawo-i-piesc/engine-antiginx/actions)
- 📝 [License](../LICENSE)