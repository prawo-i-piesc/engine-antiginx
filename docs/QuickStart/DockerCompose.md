# 🧩 Quick Start — Docker Compose
This variant runs `Engined` as a container service ready to work with RabbitMQ.


<br>


## ✅ Requirements
- Docker + Docker Compose
- Running RabbitMQ instance
- Existing Docker network `antiginx` (defined as `external`)

**Create the network (one-time setup) if you don't have it:**
```bash
docker network create antiginx
```


<br>


## 1️⃣ Prepare `.env` File
Create a `.env` file in the project root directory:
```dotenv
ENGINE_PORT=5000
BACK_URL=http://backend:3000/api/results
RABBITMQ_URL=amqp://guest:guest@rabbitmq:5672/
```


<br>


**📋 About Environment Variables:**

- `ENGINE_PORT` is used by `docker-compose.yml` for port mapping (`${ENGINE_PORT}:5000`).
- `BACK_URL` and `RABBITMQ_URL` are passed into the container as environment variables.


<br>


## 2️⃣ Create `docker-compose.yml`
Create or update the `docker-compose.yml` file in your project root:
```yaml
version: '3.8'

services:
  engine-antiginx:
    image: ghcr.io/prawo-i-piesc/engine-antiginx:latest
    container_name: engine-antiginx-worker
    restart: unless-stopped
    
    ports:
      - "${ENGINE_PORT}:5000"
    
    environment:
      - RABBITMQ_URL=${RABBITMQ_URL}
      - BACK_URL=${BACK_URL}
    
    mem_limit: 1024m
    
    networks:
      - antiginx

networks:
  antiginx:
    external: true
```

**💡 Customization:**

- Change `ghcr.io/prawo-i-piesc/engine-antiginx:latest` to your own registry if needed.
- Adjust `mem_limit` based on your scan complexity and server capacity.


<br>


## 3️⃣ Start Services
Start the container in detached mode:
```bash
docker compose up -d
```


<br>


## ✅ Quick Validation
Check status:
```bash
docker compose ps
```

View logs:
```bash
docker compose logs -f engine-antiginx
```


<br>


## 4️⃣ Stop Services
Stop and remove containers:
```bash
docker compose down
```


<br>


## 🔄 How It Works
- Container launches the `/engine-antiginx/Engined` binary.
- Worker consumes messages from the `scan_queue` queue.
- Each task message (JSON format) triggers a scan via `App` (`rawjson` mode).
- Results and errors are ACK/NACK'd according to retry logic.


<br>


## 📤 Message Format Example
When sending a task to RabbitMQ, use this JSON structure:
```json
{
	"Target": "https://example.com",
	"Parameters": [
		{
			"Name": "--tests",
			"Arguments": ["https", "hsts", "serv-h-a"]
		},
		{
			"Name": "--taskId",
			"Arguments": ["task-123"]
		}
	]
}
```


<br>


## 🔧 Troubleshooting
- **Error: `network antiginx declared as external, but could not be found`** → Create the network: `docker network create antiginx`.
- **Empty/incorrect `RABBITMQ_URL`** → Update `.env` and restart with `docker compose up -d`.
- **No results reaching backend** → Verify the `BACK_URL` endpoint is reachable from the container network.
- **Worker keeps crashing** → Check logs with `docker compose logs -f engine-antiginx` and verify RabbitMQ connectivity.
