package execution

import "Engine-AntiGinx/App/parser/config/types"

// Formatter defines the contract for converting parsed user input into an actionable execution plan.
type Formatter interface {

	// FormatParameters maps parsed command parameters to an execution Plan.
	FormatParameters(params []*types.CommandParameter) *Plan
}
