# Execution plans and strategies

`App/execution` connects parsed parameters to `App/Runner`. A formatter constructs an execution `Plan`; the runner executes the strategies in that plan, and the strategies publish results to the reporter through a channel. This layer is distinct from `App/SiteTests`: strategies select and schedule tests, while tests evaluate the target.

## Plans and formatting

| API | Purpose |
|---|---|
| `execution.Formatter.FormatParameters(params)` | Converts parsed `CommandParameter` values into a `*Plan`. |
| `execution.Plan` | Holds the operator-supplied `Target`, `AntiBotFlag`, ordered `Strategies`, `Contexts` keyed by `GetName()`, `TaskId`, and `IsHelp`. |
| `formatterImpl.InitializeFormatter(getStrategy)` | Creates a scan formatter with an injected strategy lookup. |
| `formatterImpl.NewHelpFormatter(getHelpStrategy)` | Creates a help formatter with a separate strategy lookup. |

`ScanFormatter` takes the target from the first parameter, recognizes `--antiBotDetection`, and maps the remaining parameters to strategies and contexts (`Target` and `Args`). Parameters that do not match a strategy are ignored during this mapping. If `--all` appears, it replaces the other strategies with a single entry regardless of their order. If the `BACK_URL` environment variable exists, `--taskId` is required; if it is absent, formatting panics with `Errors.Error` code 101. Without `BACK_URL`, the plan's task ID remains empty.

`HelpFormatter` rejects a present `BACK_URL` (panic, code 100). With no parameters it selects the general help strategy (`""`); otherwise it maps each name to a help strategy, panicking with code 102 on a missing match. A help plan has `IsHelp: true` and no target or task ID.

## Strategies and results

`strategy.TestStrategy` defines `Execute(TestContext, chan ResultWrapper, *sync.WaitGroup, bool)`, `GetName()`, and `GetPreferredReporterType()`. `TestContext` carries `Target` and `Args`. The registry in `strategyImpl` initializes two scan strategies (`--tests`, `--all`) and two help strategies (`""`, `--tests`); duplicate names within a registry panic with code 100. `GetStrategy` and `GetHelpStrategy` return a strategy and a found flag.

`--tests` resolves each test ID through `Registry.GetTest` (unknown IDs panic with code 100), while `--all` uses `Registry.GetAllTests`. Both call `RunPhases`. Help strategies assemble a `HelpStrategyResult` from a header and `HelpSection` values, publish it asynchronously, and prefer `HelpReporter`. Scan strategies prefer `CLIReporter`; the runner delegates the actual choice to the reporter resolver. `ResultWrapper` can carry a test result, request information, or help text, accessible through `GetTestResult`, `GetReqInfo`, and `GetHelpMessage`. `RequestInfo.Code == 0` indicates a successful content load.

## Scan phases

`PhaseRun` holds the selected tests, `ResponseTarget`, `CanonicalTarget`, an injectable `LoadContent` (`ContentLoader`), and the anti-bot flag. `RunPhases` groups tests by `GetKind()`:

| Phase | Input | If fetching the page fails |
|---|---|---|
| `PreResponse` | Canonical URL (HTTPS) | Still runs. |
| `Structure` | Canonical URL (HTTPS) | Still runs. |
| `Response` (also the default for unrecognized kinds) | Response after redirects and a copy of the page body | Skipped; the message lists the IDs of skipped tests. |

`PreResponse` and `Structure` tests start before the page is fetched. Each test runs in its own goroutine registered with the `WaitGroup`. If there are no `Response` tests, the main page is not fetched. On a successful fetch, the response body is read once into `ScanContext.Body`; when available, the response's URL replaces the target in the `Response` context so tests see the redirected URL. `RunPhases` returns after starting tests; its caller waits on the `WaitGroup` before closing the result channel.

`LoadWebsiteContent` creates a client with `User-Agent: AntiGinx-TestClient/1.0` and optionally enables `WithAntiBotDetection`. It converts client panics to `RequestInfo` (HTTP client codes 100 for request creation, 101 for network failures, 102 for status failures, 200 for body reads, and 300 for challenges); unexpected panics use code 999. It makes up to two attempts, separated by two seconds even for non-retryable failures. On success it returns the response and code 0. Detected protections are preserved in `Protections`.

`WrapRequestFailure` normally publishes a request failure as process information. If the failure identifies a protection provider and no `BotProtection`-category test was started in `PreResponse`, it instead constructs a `BotProtectionTest.NewVerdict` result, avoiding duplicate reporting. `PerformTest` runs `Test.Run`, publishes the wrapped result, and calls `wg.Done()`; it does not recover panics from tests.

## Files

- `ExecutionPlan.go`, `Formatter.go` — plan and formatter contracts.
- `formatterImpl/` — scan and help formatters.
- `strategy/Types.go`, `strategy/test_strategy.go` — interfaces and result transport.
- `strategy/StrategyHelper.go` — content loading, phase scheduling, and request-failure handling.
- `strategy/strategyImpl/` — concrete strategies and their registries.

[`Helpers`](../Helpers/README.md) constructs target URLs; [`HTTP`](../HTTP/README.md) performs individual requests.
