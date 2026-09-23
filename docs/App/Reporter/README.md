# Reporter

`App/Reporter` consumes `strategy.ResultWrapper` values from the runner's channel. `Reporter.StartListening() <-chan int` starts a consumer goroutine and returns a completion channel carrying a failure count. The caller must close the input channel after all producers finish, then receive from the completion channel. The implementations send one value; they do **not** close the completion channel. A wrapper can contain a test result, request information, or a help message; each reporter handles the kinds it supports.

## Selection and API

`NewResolver() *ConcreteResolver` implements `Resolver.Resolve(ch, taskId, target, clientTimeOut, retryDelay, strategies) Reporter`. It first requires at least one strategy (panic `Errors.Error` code 100) and identical preferred reporter types across strategies (code 101 if mixed). If that preference is `HelpReporter`, it returns `NewHelpReporter(ch)`. Otherwise, if the `BACK_URL` environment variable **exists** (even if empty), it returns `InitializeBackendReporter(ch, BACK_URL, taskId, target, clientTimeOut, retryDelay)`; otherwise it uses `InitializeCliReporter(ch)`. Other preferences do not prevent the environment-based backend selection. Neither the resolver nor runner checks that `taskId` is nonempty.

The constructors return concrete unexported implementation types that satisfy the exported `Reporter` interface. `clientTimeOut` and `retryDelay` are seconds; the backend constructor fixes `maxRetries` at 2, so a retryable result can be sent up to three times (initial attempt plus two retries).

| Reporter | Output and completion |
|---|---|
| CLI | Prints a banner and `TEST RESULT`, then each result's name, certainty, threat level, description and a separator to stdout. Request-info wrappers print a content-load message instead. The output currently spells the certainty label `Certanity` and prints `Threat level` without a colon. An invalid wrapper (neither result nor request info) panics with code 100. Sends `0` when the input closes. |
| Help | Prints a help banner, header and sections separated by lines to stdout. Requires each wrapper to hold a help message; otherwise panics with code 100. Sends `0` after the input closes. |
| Backend | POSTs JSON to `BACK_URL` with `Content-Type: application/json`, tracking permanently failed uploads. Request-info wrappers are sent immediately as message payloads rather than through the normal result retry queue. Completion signalling is described below. |

## Backend payload and failure handling

`types.TestResultWrapper` serializes as `target`, `testId`, `result` (`SiteTests.TestResult`), `endFlag`, `resultType` and `message` (`strategy.RequestInfo`). `ResultType` is an integer: `Message = 0`, `Success = 1`. Normal results use `Success`, `endFlag: false` and process info `Test completed successfully` (code 0); request-info wrappers use `Message`, `endFlag: false` and an empty test result. When the input and retry queue have drained **and the failure count is zero**, the backend sends a final empty result with `endFlag: true`. If any uploads failed, that end marker is not sent. The final marker (and each request-info message) uses `sendLastWithFlag`: at most one additional attempt on a retryable error, then increments the failure count on failure.

For ordinary results, network errors and non-2xx HTTP responses outside the 4xx range are retryable; 4xx and JSON/request-creation errors are not. The retry queue has capacity 10; a sleeping goroutine waits `retryDelay` seconds before re-enqueueing a failed result. This is a **fixed delay**, not exponential backoff. The HTTP client timeout is `clientTimeOut` seconds per request. A wrapper without a test result on the ordinary-result path increments the failure count. The reporter waits for pending retry goroutines and queued retries before signalling completion; the returned count is the number of permanently failed submissions, not total attempts.

| `Errors.Error` code | Cause | Retryable |
|---|---|---|
| 100 | JSON marshaling | No |
| 101 | HTTP request creation | No |
| 102 | HTTP client/network error | Yes |
| 103 | Non-2xx HTTP status | Yes for <400 or >=500; no for 4xx |

The backend endpoint must accept this JSON format and a 2xx response indicates success. There is no idempotency handling in the reporter: retries may deliver the same payload more than once. A missing/invalid URL fails at request creation or dispatch rather than causing an automatic CLI fallback.
