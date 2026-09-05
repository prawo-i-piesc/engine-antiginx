package strategy

import (
	HttpClient "Engine-AntiGinx/App/HTTP"
	"Engine-AntiGinx/App/SiteTests"
	"Engine-AntiGinx/App/SiteTests/BotProtectionTest"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// LoadWebsiteContent fetches the target website content via HTTP GET request and returns
// the response for sharing across all test executions. This function performs a single
// HTTP request to avoid redundant network calls for each test.
//
// The function creates an HTTP client with custom headers to identify the scanner and
// executes a GET request against the target URL. The returned response object is then
// shared among all concurrent test goroutines.
//
// HTTP configuration:
//   - User-Agent: "AntiGinx-TestClient/1.0" (identifies the scanner)
//   - Method: GET
//   - Timeout: Configured in HttpClient wrapper (default: 30 seconds)
//
// Failures are recovered internally and returned as a RequestInfo rather than propagated
// as a panic. The RequestInfo carries:
//   - Request creation failure (code 100)
//   - Network error (code 101)
//   - Non-200 status code (code 102)
//   - Response body reading failure (code 200)
//   - Bot protection detected (code 300)
//
// When the failure came from an identified bot protection product, RequestInfo.Protections
// names it. See WrapRequestFailure for how that changes the way the failure is reported.
//
// Parameters:
//   - target: The fully qualified URL to request (e.g., "https://example.com")
//
// Returns:
//   - *http.Response: Raw HTTP response object to be shared across all tests
//
// Example:
//
//	response := loadWebsiteContent("https://example.com", true)
//	// Response contains headers, body, status code, etc.
//	// This single response is analyzed by all tests
func LoadWebsiteContent(target string, useAntiBotDetection bool) (*http.Response, *RequestInfo) {
	opts := []HttpClient.WrapperOption{
		HttpClient.WithHeaders(map[string]string{
			"User-Agent": "AntiGinx-TestClient/1.0",
		}),
	}
	if useAntiBotDetection {
		opts = append(opts, HttpClient.WithAntiBotDetection())
	}
	httpClient := HttpClient.CreateHttpWrapper(opts...)
	var content *http.Response
	var reqInfo *RequestInfo

	for i := 0; i < 2; i++ {
		panicTriggerred := false
		func() {
			defer func() {
				if r := recover(); r != nil {
					panicTriggerred = true
					switch val := r.(type) {
					case HttpClient.HttpError:
						reqInfo = &RequestInfo{
							Message:     val.Message,
							Code:        val.Code,
							Protections: val.Protections,
						}
						if !val.IsRetryable {
							return
						}
					default:
						reqInfo = &RequestInfo{
							Message: "Unknown error occurred",
							Code:    999,
						}
					}
				}
			}()
			content = httpClient.Get(target)
		}()
		if !panicTriggerred {
			return content, &RequestInfo{
				Message: "Content loaded successfully",
				Code:    0,
			}
		}
		if i < 1 {
			time.Sleep(time.Second * 2)
		}
	}
	return nil, reqInfo
}

// ContentLoader fetches the target's main page. It matches LoadWebsiteContent and exists
// so strategies can inject a stub in tests without reaching the network.
type ContentLoader func(target string, useAntiBotDetection bool) (*http.Response, *RequestInfo)

// PhaseRun describes one scan: the tests selected for it and everything needed to feed
// each execution phase its input.
//
// Two targets are carried rather than one because the phases disagree about the scheme.
// ResponseTarget honours the operator's test selection, which downgrades to http:// when
// the https or hsts test is present. CanonicalTarget is always https:// and is what the
// PreResponse and Structure phases analyse.
//
// Fields:
//   - Tests: Tests selected for this scan, of any kind and in any order
//   - ResponseTarget: URL fetched for the Response phase
//   - CanonicalTarget: URL analysed by the PreResponse and Structure phases
//   - LoadContent: Fetches the main page, injected for testability
//   - AntiBotFlag: Whether to enable anti-bot detection on the main request
type PhaseRun struct {
	Tests           []SiteTests.Test
	ResponseTarget  string
	CanonicalTarget *url.URL
	LoadContent     ContentLoader
	AntiBotFlag     bool
}

// RunPhases schedules every selected test into the phase its kind calls for and starts it.
//
// The phases differ in one decisive respect: only the Response phase needs the main page.
// PreResponse and Structure tests reach their own conclusions from the target itself, so
// they are started first and run while the fetch is still in flight, and a fetch that
// fails takes down nothing but the Response phase. That is the whole point of the split:
// a target behind a bot protection challenge still gets its URL analysed and its
// certificate, sitemap and infrastructure inspected.
//
// The main page is fetched only when at least one Response test was actually selected,
// so a scan of nothing but structural tests never issues the request at all.
//
// The function returns once every test has been started and the WaitGroup has been
// incremented for each, so the caller can safely Wait on it. Results arrive on the
// channel asynchronously.
//
// Parameters:
//   - run: The scan to execute
//   - channel: Channel results are published to
//   - wg: WaitGroup incremented once per started test
func RunPhases(run PhaseRun, channel chan ResultWrapper, wg *sync.WaitGroup) {
	preTests, responseTests, structureTests := bucketByKind(run.Tests)

	// Started before the fetch so they overlap with it instead of queueing behind it.
	targetContext := SiteTests.ScanContext{Target: run.CanonicalTarget}
	startTests(preTests, targetContext, channel, wg)
	startTests(structureTests, targetContext, channel, wg)

	if len(responseTests) == 0 {
		return
	}

	response, reqInfo := run.LoadContent(run.ResponseTarget, run.AntiBotFlag)
	if reqInfo.Code != 0 {
		channel <- WrapRequestFailure(withSkippedTests(reqInfo, responseTests), reportsBotProtection(preTests))
		return
	}

	// The response's own URL is preferred over the requested one so tests see where the
	// target actually redirected them.
	responseContext := SiteTests.ScanContext{Target: run.CanonicalTarget, Response: response}
	if response.Request != nil && response.Request.URL != nil {
		responseContext.Target = response.Request.URL
	}
	startTests(responseTests, responseContext, channel, wg)
}

// bucketByKind splits selected tests into one slice per execution phase.
//
// Parameters:
//   - tests: Tests to split, of any kind
//
// Returns:
//   - []SiteTests.Test: PreResponse tests
//   - []SiteTests.Test: Response tests
//   - []SiteTests.Test: Structure tests
func bucketByKind(tests []SiteTests.Test) (pre, response, structure []SiteTests.Test) {
	for _, test := range tests {
		switch test.GetKind() {
		case SiteTests.PreResponse:
			pre = append(pre, test)
		case SiteTests.Structure:
			structure = append(structure, test)
		default:
			response = append(response, test)
		}
	}
	return pre, response, structure
}

// startTests launches one goroutine per test and increments the WaitGroup for each.
// The WaitGroup is incremented on the calling goroutine so the caller can Wait as soon
// as startTests returns.
//
// Parameters:
//   - tests: Tests to start
//   - ctx: Scan context handed to every one of them
//   - channel: Channel results are published to
//   - wg: WaitGroup incremented once per test
func startTests(tests []SiteTests.Test, ctx SiteTests.ScanContext, channel chan ResultWrapper, wg *sync.WaitGroup) {
	for _, test := range tests {
		wg.Add(1)
		go PerformTest(test, wg, channel, ctx)
	}
}

// withSkippedTests annotates a failed request with the tests it cost, so the operator
// reads which findings are missing rather than inferring it from a shorter report.
//
// Parameters:
//   - info: The failure reported by the content loader
//   - skipped: Response tests that could not run because of it
//
// Returns:
//   - *RequestInfo: The failure with the skipped tests named in its message
func withSkippedTests(info *RequestInfo, skipped []SiteTests.Test) *RequestInfo {
	if info == nil || len(skipped) == 0 {
		return info
	}
	ids := make([]string, 0, len(skipped))
	for _, test := range skipped {
		ids = append(ids, test.GetId())
	}
	annotated := *info
	annotated.Message += fmt.Sprintf(
		"\nSkipped %d test(s) that need the page content: %s",
		len(ids), strings.Join(ids, ", "),
	)
	return &annotated
}

// PerformTest executes a single security test in a separate goroutine and publishes
// the result to the shared results channel. This function is designed to be called
// as a goroutine and implements the worker pattern for concurrent test execution.
//
// Workflow:
//  1. Execute the test's Run method against the scan context
//  2. Send the TestResult to the results channel
//  3. Signal completion via WaitGroup (deferred)
//
// The function uses defer wg.Done() to ensure the WaitGroup is always decremented,
// even if the test panics or encounters an error. This guarantees proper synchronization
// and prevents deadlocks in the orchestration logic.
//
// Concurrency considerations:
//   - Thread-safe: Multiple goroutines can call this function concurrently
//   - Shared context: Tests in one phase receive the same context object (read-only)
//   - Channel communication: Results are sent to buffered channel (non-blocking)
//   - Synchronization: WaitGroup ensures proper cleanup
//
// Parameters:
//   - test: The test to execute, of any kind
//   - wg: WaitGroup for synchronizing test completion
//   - results: Send-only channel for publishing test results
//   - ctx: Scan context providing the target and, in the Response phase, the response
//
// Example usage (called by RunPhases):
//
//	wg.Add(1)
//	go PerformTest(httpsTest, &wg, resultChannel, scanContext)
//	// Test runs concurrently, result sent to channel, WaitGroup decremented
func PerformTest(test SiteTests.Test, wg *sync.WaitGroup, results chan<- ResultWrapper, ctx SiteTests.ScanContext) {
	defer wg.Done()
	testResult := test.Run(ctx)
	wrapped := WrapStrategyResult(&testResult, nil, nil)
	results <- wrapped
}

// WrapRequestFailure converts a failed content load into the wrapper that should be sent
// to the reporting layer.
//
// Most failures are just that, and are forwarded as process information so the operator
// sees why the Response phase produced nothing. A failure caused by an identified bot
// protection product is different: it carries a real signal about the target and is
// forwarded as a security verdict instead, so it appears in the report alongside ordinary
// findings.
//
// That substitution only happens when the scan has no bot protection test of its own.
// With one selected, the dedicated test has already probed the target and reported a
// verdict from evidence, and synthesizing a second one from the failed request would put
// two findings with the same name and different conclusions in front of the operator.
//
// The two wrapper forms are mutually exclusive on purpose. Both reporters check for
// process information first and skip the test result when it is present, so a verdict is
// only visible when the process information is left out.
//
// Parameters:
//   - info: The RequestInfo describing the failed content load
//   - hasBotProtectionTest: Whether the scan already runs a bot protection test
//
// Returns:
//   - ResultWrapper: A verdict-bearing wrapper for an identified bot protection block,
//     otherwise a process-information wrapper
func WrapRequestFailure(info *RequestInfo, hasBotProtectionTest bool) ResultWrapper {
	if info == nil || len(info.Protections) == 0 || hasBotProtectionTest {
		return WrapStrategyResult(nil, nil, info)
	}

	verdict := BotProtectionTest.NewVerdict(info.Protections, info.Message, info.Code)
	return WrapStrategyResult(&verdict, nil, nil)
}

// reportsBotProtection reports whether any of the given tests already covers the bot
// protection layer, so the failure path knows not to synthesize a competing verdict.
//
// The check is by category rather than by test id, so a future bot protection test is
// recognised without the scheduler having to learn its name.
//
// Parameters:
//   - tests: Tests selected for the scan
//
// Returns:
//   - bool: true when at least one test carries the bot protection category
func reportsBotProtection(tests []SiteTests.Test) bool {
	for _, test := range tests {
		if test.GetCategory() == BotProtectionTest.Category {
			return true
		}
	}
	return false
}
