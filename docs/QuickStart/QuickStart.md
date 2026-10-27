# 🚀 Quick Start
Welcome to **Engine-AntiGinx** — a lightweight engine for automated security testing.
This section guides you from zero to your first scan in just a few minutes.


<br>


## 📋 What do you want to run?
| Scenario | Best Path | Best For |
|---|---|---|
| Quick scan from terminal | [CLI](./CLI.md) | Developers, Pentesters |
| Scan via pre-built image | [Docker](./Docker.md) | DevOps, CI/CD |
| Scan with a locally built image | [Docker Compose](./DockerCompose.md) | Local development |



<br>


## ✅ Requirements
- **Go 1.26.8+** (for local CLI mode)
- **Docker** (for running the CLI image or Docker Compose)


<br>


**🔧 Versions & Compatibility:**

- `go.mod` specifies `go 1.26.8`.
- The multi-stage image contains the `App` CLI binary only; the daemon is maintained in a separate repository.


<br>


## 1️⃣ Quick Start Locally (Go)
Clone the project to your local machine:
```bash
git clone https://github.com/prawo-i-piesc/engine-antiginx.git
```

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

**What this command does:**

- runs `test` mode,
- executes `https`, `hsts`, and `serv-h-a` tests,
- returns the report directly to your console.


<br>


## 🎯 What's Next?
- Want full parameter docs and all available tests? → [CLI Guide](./CLI.md)
- Want to run via container image? → [Docker Guide](./Docker.md)
- Want to build and run locally with Compose? → [Docker Compose Guide](./DockerCompose.md)
