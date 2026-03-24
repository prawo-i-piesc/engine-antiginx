# 🐳 Quick Start — Docker
Run Engine-AntiGinx in a container without a local Go installation.


<br>


## ✅ Requirements
- Docker 24+
- Internet access (to pull image / scan targets)
- RabbitMQ (if running `Engined`)


<br>


## Option A: Pre-built Image from GHCR 

### Pull the Latest Image
```bash
docker pull ghcr.io/prawo-i-piesc/engine-antiginx:latest
```

### Scan from Container (CLI `App`)
```bash
docker run --rm \
	ghcr.io/prawo-i-piesc/engine-antiginx:latest \
	/engine-antiginx/App test --target example.com --tests https hsts serv-h-a
```

### JSON File Mode
```bash
docker run --rm \
	-v "$PWD":/work \
	-w /work \
	ghcr.io/prawo-i-piesc/engine-antiginx:latest \
	/engine-antiginx/App json ./scan.json
```

### Raw JSON Mode (stdin)
```bash
cat scan.json | docker run --rm -i \
	ghcr.io/prawo-i-piesc/engine-antiginx:latest \
	/engine-antiginx/App rawjson
```


<br>


## Option B: Build Image Locally

### Build the Image
```bash
docker build -t engine-antiginx:local .
```

### Scan from Container (CLI `App`)
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


## 🛠️ Notes
- The image contains both `App` and `Engined` binaries built in a multi-stage Dockerfile.
- `App` is used for CLI scanning, while `Engined` is the background worker that processes RabbitMQ tasks.


<br>


## 🔧 Troubleshooting
- **`RABBITMQ_URL environment variable is not set`** → Add `-e RABBITMQ_URL=...`.
- **Cannot connect to RabbitMQ** → Check host, port, credentials, and container network.
- **Target scan fails** → Verify the domain is reachable from the container.
