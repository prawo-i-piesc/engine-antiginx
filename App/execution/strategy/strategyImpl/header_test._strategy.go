package strategyImpl

import (
	error "Engine-AntiGinx/App/Errors"
	"Engine-AntiGinx/App/SiteTests"
	"Engine-AntiGinx/App/execution/strategy"
	"fmt"
	"net/url"
	"sync"
)

// headerTestStrategy implements the strategy.TestStrategy interface.
// It is responsible for orchestrating header-based security assessments
// by fetching target content and executing a suite of sub-tests concurrently.
type headerTestStrategy struct {
	loadWebsiteContent strategy.ContentLoader
	getTest            func(testId string) (SiteTests.Test, bool)
	format             func(target string, params []string) *string
	canonicalize       func(target string) *url.URL
}

// InitializeHeaderStrategy returns a pointer to a new headerTestStrategy.
// It acts as the constructor for the header-based testing logic.
func InitializeHeaderStrategy(loadWebsiteContent strategy.ContentLoader,
	getTest func(testId string) (SiteTests.Test, bool),
	format func(target string, params []string) *string,
	canonicalize func(target string) *url.URL) *headerTestStrategy {
	return &headerTestStrategy{
		loadWebsiteContent: loadWebsiteContent,
		getTest:            getTest,
		format:             format,
		canonicalize:       canonicalize,
	}
}

// Execute performs the strategy logic by fetching the target website's content
// and spawning asynchronous sub-tests for each provided argument.
//
// Concurrency Model:
//   - It utilizes a sync.WaitGroup to track the lifecycle of spawned goroutines.
//   - Results are streamed back to the orchestrator via the provided result channel.
//
// Logic Flow:
//  1. Formats the target URL using the format helper.
//  2. Fetches the raw website content (respecting the antiBotFlag). A failed fetch ends
//     the strategy early, reported either as process information or, when an identified
//     bot protection layer blocked it, as a security verdict.
//  3. Iterates through ctx.Args to identify specific sub-tests in the Registry.
//  4. Launches each valid sub-test in its own goroutine.
//
// Panic Behavior:
//
//	If an argument corresponds to a test ID that does not exist in the Registry,
//	the function panics with an error.Error (code 100), which is caught by the
//	global ErrorHandler.
func (h *headerTestStrategy) Execute(ctx strategy.TestContext, channel chan strategy.ResultWrapper, wg *sync.WaitGroup, antiBotFlag bool) {
	selected := make([]SiteTests.Test, 0, len(ctx.Args))
	for _, val := range ctx.Args {
		t, ok := h.getTest(val)
		if !ok {
			panic(error.Error{
				Code:        100,
				Message:     fmt.Sprintf("Parsing error occurred. This could be due to:\n- test with Id %s does not exists", val),
				Source:      "Header Test Strategy",
				IsRetryable: false,
			})
		}
		selected = append(selected, t)
	}

	strategy.RunPhases(strategy.PhaseRun{
		Tests:           selected,
		ResponseTarget:  *h.format(ctx.Target, ctx.Args),
		CanonicalTarget: h.canonicalize(ctx.Target),
		LoadContent:     h.loadWebsiteContent,
		AntiBotFlag:     antiBotFlag,
	}, channel, wg)
}

func (h *headerTestStrategy) GetName() string {
	return "--tests"
}

// GetPreferredReporterType returns the default ReporterType that should be used when
// running this strategy in the absence of any environment-based override.
//
// Centralized configuration (for example, environment variables such as BACK_URL)
// may override this preference at runtime to route results to a different reporter,
// but individual strategies should declare their preferred type to keep behavior
// consistent as more reporter types are introduced.
func (h *headerTestStrategy) GetPreferredReporterType() strategy.ReporterType {
	return strategy.CLIReporter
}
