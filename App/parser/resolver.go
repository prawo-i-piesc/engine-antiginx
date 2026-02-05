package parser

import (
	"Engine-AntiGinx/App/Errors"
	"Engine-AntiGinx/App/Helpers"
	"Engine-AntiGinx/App/parser/impl"
	"os"
)

// Resolver is responsible for selecting the appropriate Parser implementation
// based on the command-line arguments provided by the user.
// It acts as a router that directs execution to the specific worker (e.g., JsonParser, CommandParser).
type Resolver struct{}

// parserEntry is a wrapper struct used internally to hold a reference to a concrete Parser instance.
type parserEntry struct {
	workerReference Parser
}

// whiteList serves as a registry mapping command strings (e.g., "json", "test")
// to their corresponding Parser implementations.
// This map is initialized on startup and effectively acts as a strategy pattern registry.
var whiteList = map[string]parserEntry{

	"test": {
		workerReference: impl.CreateCommandParser(),
	},

	"json": {
		workerReference: impl.CreateJsonParser(helpers.CreateFileReader()),
	},

	"rawjson": {
		workerReference: impl.CreateRawJsonParser(os.Stdin),
	},

	// Will be implemented soon
	//"help" : {
	//	workerReference: CreateHelpParser(),
	//},
}

// CreateResolver initializes and returns a new instance of the Resolver service.
func CreateResolver() *Resolver {
	return &Resolver{}
}

// Resolve determines which Parser to use by inspecting the second argument (index 1)
// of the provided parameters (usually os.Args).
//
// It performs the following checks:
//   - Verifies that enough parameters are provided (requires at least 2: [executable, command]).
//   - Looks up the command in the internal whitelist.
//
// Returns the matching Parser interface if successful.
// Panics if:
//   - Fewer than 2 arguments are provided (Error 100).
//   - The requested worker/command is not found in the whitelist (Error 101).
func (p *Resolver) Resolve(userParameters []string) Parser {
	length := len(userParameters)
	if length < 2 {
		panic(Errors.Error{
			Code: 100,
			Message: `Parsing error occurred. This could be due to:
				- insufficient number of parameters`,
			Source:      "Resolver",
			IsRetryable: false,
		})
	}

	workerParam := userParameters[1]
	worker, ok := whiteList[workerParam]
	if !ok {
		panic(Errors.Error{
			Code: 101,
			Message: `Parsing error occurred. This could be due to:
				- invalid worker param`,
			Source:      "Resolver",
			IsRetryable: false,
		})
	}
	return worker.workerReference
}
