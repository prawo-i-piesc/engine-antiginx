package strategy

import (
	"sync"
)

type ReporterType int

const (
	CLIReporter ReporterType = iota
	HelpReporter
)

// TestStrategy defines the contract for a family of security testing algorithms.
type TestStrategy interface {
	// Execute runs the strategy, publishing results to channel and tracking workers in wg.
	Execute(ctx TestContext, channel chan ResultWrapper, wg *sync.WaitGroup, antiBotFlag bool)

	// GetName returns the strategy registry key (for example, "--tests").
	GetName() string
	GetPreferredReporterType() ReporterType
}

// TestContext encapsulates the specific data required for a TestStrategy to run.
type TestContext struct {
	// Target represents the base URL or host intended for the security scan.
	Target string

	// Args holds the arguments selected for this strategy.
	Args []string
}
