# 🧩 Quick Start — Docker Compose

This Compose file builds the scanner CLI from this repository. The daemon is maintained separately; this service does not listen on a port or run continuously.

## Build the image

From the repository root:

```bash
docker compose build engine-antiginx
```

## Run a scan

```bash
docker compose run --rm engine-antiginx test --target example.com --tests https hsts serv-h-a
```

Run without a command to display help:

```bash
docker compose run --rm engine-antiginx
```

To send JSON on stdin, disable Compose's pseudo-TTY with `-T`:

```bash
docker compose run --rm -T engine-antiginx rawjson < scan.json
```

The optional `ANTIGINX_NVD_API_KEY` and `ANTIGINX_URLHAUS_AUTH_KEY` environment variables are forwarded from your shell when set. They are not required for basic scans.

Use `docker compose run`, not `docker compose up -d`: a scan is a one-off command, and the default `help` command exits after printing usage.
