# 🐳 Quick Start — Docker

The image contains the `App` scanner CLI, not the daemon. It runs a command and exits; deploy the daemon from its separate repository.

## Requirements

- Docker
- Network access to pull the image and reach scan targets

## Pre-built image

```bash
docker pull ghcr.io/prawo-i-piesc/engine-antiginx:latest
```

Running the image without arguments prints CLI help:

```bash
docker run --rm ghcr.io/prawo-i-piesc/engine-antiginx:latest
```

Run a scan by passing a CLI command after the image name:

```bash
docker run --rm ghcr.io/prawo-i-piesc/engine-antiginx:latest \
  test --target example.com --tests https hsts serv-h-a
```

For JSON input from a file, mount the file's directory and use its container path:

```bash
docker run --rm -v "$PWD":/work:ro \
  ghcr.io/prawo-i-piesc/engine-antiginx:latest json /work/scan.json
```

For raw JSON via stdin, keep stdin open with `-i`:

```bash
docker run --rm -i ghcr.io/prawo-i-piesc/engine-antiginx:latest rawjson < scan.json
```

## Build locally

```bash
docker build -t engine-antiginx:local .
docker run --rm engine-antiginx:local test --target example.com --tests https
```

This CLI does not listen on a port and does not need a published port or a long-running deployment. To build and run it with Compose, see the [Docker Compose guide](./DockerCompose.md).
