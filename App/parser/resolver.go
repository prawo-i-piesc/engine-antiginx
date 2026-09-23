package parser

import (
	"Engine-AntiGinx/App/Errors"
	"Engine-AntiGinx/App/Helpers"
	"Engine-AntiGinx/App/execution"
	impl2 "Engine-AntiGinx/App/execution/formatterImpl"
	"Engine-AntiGinx/App/execution/strategy/strategyImpl"
	"Engine-AntiGinx/App/parser/impl"
	"os"
)

// Resolver selects a parser and formatter for a command.
type Resolver struct{}

// parserEntry is a wrapper struct used internally to hold a reference to a concrete Parser instance.
type parserEntry struct {
	workerReference    Parser
	formatterReference execution.Formatter
}

// whiteList maps commands to their parsers and formatters.
var whiteList = map[string]parserEntry{

	"test": {
		workerReference:    impl.CreateCommandParser(),
		formatterReference: impl2.InitializeFormatter(strategyImpl.GetStrategy),
	},

	"json": {
		workerReference:    impl.CreateJsonParser(helpers.CreateFileReader()),
		formatterReference: impl2.InitializeFormatter(strategyImpl.GetStrategy),
	},

	"rawjson": {
		workerReference:    impl.CreateRawJsonParser(os.Stdin),
		formatterReference: impl2.InitializeFormatter(strategyImpl.GetStrategy),
	},

	"help": {
		workerReference:    impl.CreateHelpParser(),
		formatterReference: impl2.NewHelpFormatter(strategyImpl.GetHelpStrategy),
	},
}

// CreateResolver initializes and returns a new instance of the Resolver service.
func CreateResolver() *Resolver {
	return &Resolver{}
}

// Resolve selects the parser and formatter from the second input token.
func (p *Resolver) Resolve(userParameters []string) (Parser, execution.Formatter) {
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
	return worker.workerReference, worker.formatterReference
}
