# Engined — RabbitMQ scan consumer

`Engined/main.go` receives tasks from RabbitMQ's `scan_queue` and executes the scanner (`App`) as a subprocess, **one delivery at a time**. The flow is producer → `scan_queue` → Engined → scanner. `Engined/queueconfig.go` holds the connection, channel and connection-close notification returned during setup.

## Startup and configuration

The worker tries to load `.env`; failure prints a warning but does not stop startup. It requires both `RABBITMQ_URL` (an AMQP connection URL, for example `amqp://guest:guest@localhost:5672/`) and `ENGINE_ANTIGINX_CALL` (a scanner executable path or a name resolvable on `PATH`; it is passed to `exec.Command`, not a shell). It connects to RabbitMQ, creates a channel, and consumes from the existing `scan_queue` with auto-ack disabled. It does not declare the queue. It closes the channel and connection on normal return. `BACK_URL`, when configured for the scanner process, determines backend reporting and JSON-formatted scanner errors; the worker does not set it.

## Message body

Messages are decoded as `types.TestJson`, not as the `EngineTask` struct still declared in `Engined/main.go` (that type is unused by the consumer). The JSON fields are `Target` and `Parameters`; each parameter has `Name` and `Arguments`. A task with an ID can look like:

```json
{
  "Target": "example.com",
  "Parameters": [
    {"Name": "--tests", "Arguments": ["https", "hsts"]},
    {"Name": "--taskId", "Arguments": ["task-uuid-123"]}
  ]
}
```

The scanner's `rawjson` parser prepends a `--target` parameter from `Target` and validates the resulting list. Use a hostname without a URL scheme: the target formatter adds `https://` when constructing the canonical URL. The worker looks for `--taskId` in `Parameters` (starting after element zero) before launching the scanner. It invokes `ENGINE_ANTIGINX_CALL rawjson`, writes the original message body to the subprocess's stdin, and copies its stderr both to the worker's stderr and to a buffer for error handling. Configure `BACK_URL` in the scanner environment if backend reporting is intended; in that mode the scanner requires `--taskId`.

## Delivery outcomes

| Condition | Current action |
|---|---|
| Body cannot be decoded as JSON into `types.TestJson` | NACK with `requeue=false` |
| `--taskId` not found | ACK (drop) |
| First `x-death` entry has an `int64` `count` greater than 3 | ACK (drop) |
| Scanner exits successfully | ACK |
| Scanner fails and buffered stderr parses as an `Errors.Error` with `IsRetryable=true` | NACK with `requeue=false` |
| Scanner fails with a non-retryable JSON error or stderr that cannot be decoded as `Errors.Error` | ACK (drop) |

The retry count defaults to zero when `x-death` is absent or has another shape. Despite the “Requeuing” log line, the retryable-error branch passes `requeue=false` to `Nack`; whether that message reaches a dead-letter queue depends on RabbitMQ configuration. The worker logs failures to ACK/NACK but does not retry those operations. It checks for the presence of `--taskId`, not whether its argument is populated.

## Shutdown

The consumer registers for `os.Interrupt` (Ctrl+C). On receipt it sets the shutdown flag and leaves the loop; since it runs scans synchronously, a signal observed during a scan is handled only after that scan finishes. A RabbitMQ connection-close notification instead calls `os.Exit(1)`, bypassing deferred channel/connection closes. There is no reconnection loop or SIGTERM handler in this entry point.
