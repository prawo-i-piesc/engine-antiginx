package Reporter

import (
	"Engine-AntiGinx/App/execution/strategy"
)

// Resolver defines the contract for determining and creating the appropriate
// Reporter instance based on the execution context and configuration.
//
// Implementations of this interface are responsible for analyzing the provided
// strategies and environment settings to decide which reporting mechanism
// (e.g., CLI, Backend, Help) should be used.
type Resolver interface {

	// Resolve instantiates and returns a concrete Reporter implementation.
	//
	// It acts as a factory method that uses the provided strategies to determine
	// the correct reporting type and initializes it with the necessary context.
	//
	// Parameters:
	//  - ch: The channel used for transmitting result wrappers asynchronously
	//  - taskId: The unique identifier for the current task
	//  - target: The target endpoint or system string
	//  - clientTimeOut: The timeout duration for the client
	//  - retryDelay: The delay duration between retries
	//  - strategies: A list of TestStrategy objects to derive the preferred reporter type
	//
	// Returns:
	//  - Reporter: An initialized reporter interface ready to handle results
	Resolve(ch chan strategy.ResultWrapper, taskId string,
		target string, clientTimeOut int, retryDelay int, strategies []strategy.TestStrategy) Reporter
}
