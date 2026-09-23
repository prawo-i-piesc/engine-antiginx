# App — scanner entry point

`App/main.go` starts the Engine-AntiGinx scanner. It attempts to load `.env` (ignoring a missing file), checks whether `BACK_URL` **exists** in the environment, and passes `!exists` to `GlobalHandler.InitializeErrorHandler`. An empty but present `BACK_URL` still selects backend mode.

`GlobalHandler.RunSafe()` resolves the command, parses its arguments, formats an execution plan, and passes it to the runner. Strategies run the selected tests; the reporter resolver chooses the output destination. `RunSafe()` also recovers panics: in CLI mode it writes a human-readable error block to stderr; in backend mode it writes a JSON error to stderr. Reporter selection is separate from error formatting: when `BACK_URL` is present, the reporter sends results to that backend; otherwise it uses CLI output (apart from help's own reporter).

## Commands

The parser dispatches on the first argument after the executable:

- `test` parses CLI flags. For example: `engine-antiginx test --target example.com --tests https hsts serv-h-a`.
- `json` reads input from a JSON file; `rawjson` reads JSON bytes from stdin.
- `help` displays available help (and cannot be used with `BACK_URL` set).

For `test`, `--target` supplies the target and `--tests` accepts one or more registered test IDs; `--all` selects the all-tests strategy instead. The supported IDs and other flags are defined in `App/parser/config/paramregistry.go`, not in this entry point. The `https`, `hsts`, and `serv-h-a` IDs cover HTTPS, HSTS, and server-header checks respectively. When `BACK_URL` is present, the scan formatter requires `--taskId` in the execution parameters.

The [Engined worker](../Engined/README.md) invokes the scanner as `rawjson`, passing the queue message through stdin rather than constructing CLI flags.
