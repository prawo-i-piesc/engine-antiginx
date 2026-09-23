# GlobalHandler: application entry point and panic recovery

`App/main.go` optionally loads `.env` and checks whether `BACK_URL` is set. If it is absent, it calls `InitializeErrorHandler(true)` for text-based CLI errors; if present, it passes `false` for JSON errors. It then calls `RunSafe()`.

## Execution and recovery

`RunSafe` installs a deferred `recover()`, resolves a parser and formatter for `os.Args`, parses the arguments, builds an `execution.Plan`, and passes it to `Runner.CreateJobRunner().Orchestrate` with a reporter resolver. On normal return it prints no error. Recovery applies to panics in the current goroutine only, not to goroutines started by a strategy.

| Panic value | Reported error |
|---|---|
| `Errors.Error` value | Preserves its code, source, message, and `IsRetryable` value. |
| `HTTP.HttpError` value | Copies its code, message, and `IsRetryable` into an `Errors.Error` with source `Http Client`; other `HttpError` fields are not included. |
| Any other non-nil value | Creates an `Errors.Error` with code `999`, source `Runtime/Critical`, message `Panic: <value>`, and `IsRetryable: false`. |

After reporting a recovered panic, the handler calls `os.Exit(1)` and does not print a stack trace. These type-switch cases match values, not pointers; a panic carrying `*Errors.Error` or `*HTTP.HttpError` falls into the generic case.

## Error output

`InitializeErrorHandler(cliMode bool)` selects the output format. `printError` writes to `os.Stderr`: CLI mode prints a text block with `ERROR SOURCE`, `EXIT CODE`, `MESSAGE`, and `RETRYABLE`; JSON mode encodes `Errors.Error` with two-space indentation. If JSON encoding fails, it prints fallback text containing the encoding error and original message. This is panic reporting, not scan-result formatting; the runner's selected reporter handles scan results.
