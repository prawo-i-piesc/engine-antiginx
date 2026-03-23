# 🚀 Quick Start
Welcome to **Engine-AntiGinx** — a lightweight engine for automated security testing.

This section guides you from zero to your first scan in just a few minutes.

<br>

## 📋 What do you want to run?
| Scenario | Best Path | Best For |
|---|---|---|
| Quick scan from terminal | [CLI](./CLI.md) | Developers, Pentesters |
| Scan via pre-built image | [Docker](./Docker.md) | DevOps, CI/CD |
| Worker with RabbitMQ | [Docker Compose](./DockerCompose.md) | Backend / Queues |

<br>

## ✅ Requirements
- **Go 1.25+** (for local CLI mode)
- **Docker** (for containers)
- **Docker Compose** (for orchestration)
- **RabbitMQ** (if running `Engined`)

#### 🔧 Versions & Compatibility
- `go.mod` specifies `go 1.25`.
- Project image is built in multi-stage fashion and runs both `App` and `Engined` binaries.

<br>

## 1️⃣ Clone the Repository
Clone the project to your local machine:
```bash
git clone https://github.com/prawo-i-piesc/engine-antiginx.git
```

<br>

Navigate to the project directory:
```bash
cd engine-antiginx
```

<br>

## 2️⃣ Your First Scan (in 30 seconds)
Start a quick scan using the CLI:
```bash
go run ./App/main.go test --target example.com --tests https hsts serv-h-a
```

What this command does:

- runs `test` mode,
- executes `https`, `hsts`, and `serv-h-a` tests,
- returns the report directly to your console.

<br>

## 3️⃣ What's Next?
- Want full parameter docs and all available tests? → [CLI Guide](./CLI.md)
- Want to run via container image? → [Docker Guide](./Docker.md)
- Want a worker + queue setup? → [Docker Compose Guide](./DockerCompose.md)

### 🎯 Pro Tip
- Start with **CLI** to quickly verify your target and available tests, then move to Docker/Compose automation.
