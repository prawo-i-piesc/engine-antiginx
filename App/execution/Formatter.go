package execution

import "Engine-AntiGinx/App/parser/config/types"

// Formatter defines the contract for converting parsed user input into an
// actionable execution plan.
//
// Implementations of this interface (e.g., HelpFormatter, ScanFormatter)
// are responsible for interpreting the command parameters and configuring
// the engine's runtime behavior, strategies, and targets accordingly.
type Formatter interface {

	// FormatParameters analyzes the provided list of command parameters and
	// constructs a detailed execution Plan.
	//
	// This method encapsulates the logic for mapping raw user commands (like flags
	// and arguments) to specific internal strategies, targets, and context settings
	// required by the engine.
	//
	// Parameters:
	//  - params: A slice of CommandParameter objects derived from the input parser
	//
	// Returns:
	//  - *Plan: A pointer to the fully initialized execution plan ready for the Orchestrator
	FormatParameters(params []*types.CommandParameter) *Plan
}
