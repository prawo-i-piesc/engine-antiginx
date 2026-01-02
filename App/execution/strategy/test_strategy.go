package strategy

import (
	"Engine-AntiGinx/App/Tests"
	"sync"
)

// TestStrategy defines the contract for a family of security testing algorithms.
// Any new security test (e.g., XSS, Headers, SSL) must implement this interface
// to be compatible with the application's Orchestrator and Registry.
//
// Concurrency:
// Implementations of Execute are expected to handle their own internal
// concurrency if necessary, and must signal completion via the provided sync.WaitGroup.
type TestStrategy interface {
	// Execute runs the core logic of the security test.
	//
	// Parameters:
	//   - ctx: Contains the target URL and specific arguments for this test.
	//   - channel: A thread-safe pipe to stream TestResult objects back to the UI.
	//   - wg: A synchronization primitive used to coordinate the completion of the test.
	//   - antiBotFlag: A global setting to toggle evasion techniques during execution.
	Execute(ctx TestContext, channel chan Tests.TestResult, wg *sync.WaitGroup, antiBotFlag bool)

	// GetName returns the unique identifier for the strategy.
	// This string is used as the command-line flag (e.g., "--tests") and as
	// the key in the strategy registry.
	GetName() string
}

// TestContext encapsulates the specific data required for a TestStrategy to run.
// It separates the target environment configuration from the test's implementation.
type TestContext struct {
	// Target represents the base URL or host intended for the security scan.
	Target string

	// Args holds a slice of sub-test identifiers or specific parameters
	// passed by the user for this particular strategy.
	Args []string
}
