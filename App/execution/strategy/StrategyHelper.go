package strategy

import (
	HttpClient "Engine-AntiGinx/App/HTTP"
	"Engine-AntiGinx/App/Metrics"
	"Engine-AntiGinx/App/SiteTests"
	"Engine-AntiGinx/App/SiteTests/BotProtectionTest"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// LoadWebsiteContent fetches the target website content via HTTP GET request and returns the response for sharing across all test executions.
func LoadWebsiteContent(target string, useAntiBotDetection bool) (*http.Response, *RequestInfo) {
	slog.Info("Loading website content", slog.String("target", target))

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
		slog.Debug("Attempting to load content", slog.Int("attempt", i+1))
		panicTriggerred := false

		func() {
			defer func() {
				if r := recover(); r != nil {
					panicTriggerred = true
					switch val := r.(type) {
					case HttpClient.HttpError:
						slog.Warn("HTTP Error encountered during content load",
							slog.String("message", val.Message),
							slog.Int("code", val.Code))

						reqInfo = &RequestInfo{
							Message:     val.Message,
							Code:        val.Code,
							Protections: val.Protections,
						}
						if !val.IsRetryable {
							return
						}
					default:
						slog.Error("Unknown error occurred during content load", slog.Any("error", val))
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
			slog.Info("Content loaded successfully")
			return content, &RequestInfo{
				Message: "Content loaded successfully",
				Code:    0,
			}
		}

		if i < 1 {
			slog.Debug("Sleeping before retry", slog.Int("seconds", 2))
			time.Sleep(time.Second * 2)
		}
	}

	slog.Warn("Failed to load content after retries")
	return nil, reqInfo
}

// ContentLoader fetches the target's main page.
type ContentLoader func(target string, useAntiBotDetection bool) (*http.Response, *RequestInfo)

// PhaseRun describes one scan: the tests selected for it and everything needed to feed each execution phase its input.
type PhaseRun struct {
	Tests           []SiteTests.Test
	ResponseTarget  string
	CanonicalTarget *url.URL
	LoadContent     ContentLoader
	AntiBotFlag     bool
}

// RunPhases schedules every selected test into the phase its kind calls for and starts it.
func RunPhases(run PhaseRun, channel chan ResultWrapper, wg *sync.WaitGroup) {
	slog.Info("Starting test phases", slog.Int("totalTests", len(run.Tests)))
	preTests, responseTests, structureTests := bucketByKind(run.Tests)

	slog.Debug("Bucketed tests",
		slog.Int("preResponse", len(preTests)),
		slog.Int("response", len(responseTests)),
		slog.Int("structure", len(structureTests)))

	// Started before the fetch so they overlap with it instead of queueing behind it.
	targetContext := SiteTests.ScanContext{Target: run.CanonicalTarget}

	if len(preTests) > 0 {
		slog.Debug("Starting PreResponse tests")
		startTests(preTests, targetContext, channel, wg)
	}

	if len(structureTests) > 0 {
		slog.Debug("Starting Structure tests")
		startTests(structureTests, targetContext, channel, wg)
	}

	if len(responseTests) == 0 {
		slog.Debug("No Response tests requested, skipping content load")
		return
	}

	response, reqInfo := run.LoadContent(run.ResponseTarget, run.AntiBotFlag)

	if reqInfo.Code != 0 {
		slog.Warn("Skipping Response tests due to failed content load", slog.Int("skippedCount", len(responseTests)))
		channel <- WrapRequestFailure(withSkippedTests(reqInfo, responseTests), reportsBotProtection(preTests))
		return
	}

	// The response's own URL is preferred over the requested one so tests see where the
	// target actually redirected them.
	responseContext := SiteTests.ScanContext{Target: run.CanonicalTarget, Response: response, Body: readBody(response)}
	if response.Request != nil && response.Request.URL != nil {
		responseContext.Target = response.Request.URL
	}

	slog.Debug("Starting Response tests")
	startTests(responseTests, responseContext, channel, wg)
}

func readBody(response *http.Response) []byte {
	if response == nil || response.Body == nil {
		return nil
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		slog.Warn("Failed to read response body", slog.String("error", err.Error()))
		return nil
	}
	return body
}

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

func startTests(tests []SiteTests.Test, ctx SiteTests.ScanContext, channel chan ResultWrapper, wg *sync.WaitGroup) {
	for _, test := range tests {
		wg.Add(1)
		go PerformTest(test, wg, channel, ctx)
	}
}

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
		len(ids),
		strings.Join(ids, ", "),
	)
	return &annotated
}

// PerformTest runs one test and publishes its result; the caller starts the goroutine.
func PerformTest(test SiteTests.Test, wg *sync.WaitGroup, results chan<- ResultWrapper, ctx SiteTests.ScanContext) {
	defer wg.Done()
	slog.Debug("Executing test")

	start := time.Now()
	defer func() {
		Metrics.ObserveTestDurationTime(test.GetName(), time.Since(start).Seconds())
	}()

	testResult := test.Run(ctx)

	Metrics.IncVulnerabilitiesTotal(testResult.ThreatLevel.String(), testResult.Name, 1)

	wrapped := WrapStrategyResult(&testResult, nil, nil)
	results <- wrapped
}

// WrapRequestFailure converts a failed content load into the wrapper that should be sent to the reporting layer.
func WrapRequestFailure(info *RequestInfo, hasBotProtectionTest bool) ResultWrapper {
	if info == nil || len(info.Protections) == 0 || hasBotProtectionTest {
		return WrapStrategyResult(nil, nil, info)
	}
	verdict := BotProtectionTest.NewVerdict(info.Protections, info.Message, info.Code)
	return WrapStrategyResult(&verdict, nil, nil)
}

func reportsBotProtection(tests []SiteTests.Test) bool {
	for _, test := range tests {
		if test.GetCategory() == BotProtectionTest.Category {
			return true
		}
	}
	return false
}
