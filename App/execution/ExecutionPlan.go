package execution

import "Engine-AntiGinx/App/execution/strategy"

// Plan represents a complete blueprint for a security scanning task.
// It encapsulates all necessary configurations, the sequence of tests to be
// executed, and the specific data required for each test strategy.
//
// The structure acts as a Data Transfer Object (DTO) between the ScanFormatter
// and the JobRunner, ensuring that the execution logic is decoupled from
// the parameter parsing logic.
//
// Field Details:
//   - Target: The base URL or host being tested.
//   - AntiBotFlag: A global setting to enable stealth/evasion techniques across all tests.
//   - Strategies: An ordered slice of implementations. The order in this slice
//     defines the exact execution sequence of the security tests.
//   - Contexts: A lookup map where keys are strategy names (from GetName()) and
//     values are the specific arguments and targets for that strategy.
//   - TaskId: A unique identifier for the execution, required when reporting
//     to a backend service (BACK_URL).
//
// Usage:
//
//	plan := &Plan{
//	    Target: "https://example.com",
//	    Strategies: []strategy.TestStrategy{headerStrat, xssStrat},
//	    Contexts: map[string]strategy.TestContext{
//	        "HeaderTest": {Target: "...", Args: []string{"-v"}},
//	    },
//	}
type Plan struct {
	Target      string
	AntiBotFlag bool
	Strategies  []strategy.TestStrategy
	Contexts    map[string]strategy.TestContext
	TaskId      string
}
