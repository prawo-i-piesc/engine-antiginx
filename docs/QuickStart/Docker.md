# 🐳 Quick Start — Docker
Run Engine-AntiGinx in a container without a local Go installation.

<br>

## ✅ Requirements
- Docker 24+
- Internet access (to pull image / scan targets)
- RabbitMQ (if running `Engined`)

<br>

## Option A: Pre-built Image from GHCR 
Pull the latest image:
```bash
docker pull ghcr.io/prawo-i-piesc/engine-antiginx:latest
```

<br>

### Scan from Container (CLI `App`)
```bash
docker run --rm \
	ghcr.io/prawo-i-piesc/engine-antiginx:latest \
	/engine-antiginx/App test --target example.com --tests https hsts serv-h-a
```

<br>

### JSON File Mode
```bash
docker run --rm \
	-v "$PWD":/work \
	-w /work \
	ghcr.io/prawo-i-piesc/engine-antiginx:latest \
	/engine-antiginx/App json ./scan.json
```

<br>

### Raw JSON Mode (stdin)
```bash
cat scan.json | docker run --rm -i \
	ghcr.io/prawo-i-piesc/engine-antiginx:latest \
	/engine-antiginx/App rawjson
```

<br>

## Option B: Build Image Locally
In the project directory:

```bash
docker build -t engine-antiginx:local .
```

<br>

Run a scan:

```bash
docker run --rm engine-antiginx:local /engine-antiginx/App test --target example.com --tests https
```

<br>

## 🔄 Run Engined (RabbitMQ Worker)
Start the worker that listens for scan tasks on RabbitMQ:
```bash
docker run --rm \
	-e RABBITMQ_URL="amqp://guest:guest@host.docker.internal:5672/" \
	-e BACK_URL="http://host.docker.internal:3000/api/results" \
	ghcr.io/prawo-i-piesc/engine-antiginx:latest \
	/engine-antiginx/Engined
```

`Engined` listens for messages on the `scan_queue` and runs `App` in `rawjson` mode for each one.

<br>

## 🔍 Useful Diagnostic Commands
Check if the image is available locally.

```bash
docker images | grep engine-antiginx
```

<br>

List all containers (running and stopped) to check if your scan ran or if there were errors.
```bash
docker ps -a
```

<br>

View logs for a specific container to debug scan execution or RabbitMQ connectivity issues.
```bash
docker logs <container_id>
```

<br>

## 🛠️ Troubleshooting
- **`RABBITMQ_URL environment variable is not set`** → Add `-e RABBITMQ_URL=...`.
- **Cannot connect to RabbitMQ** → Check host, port, credentials, and container network.
- **Target scan fails** → Verify the domain is reachable from the container.
