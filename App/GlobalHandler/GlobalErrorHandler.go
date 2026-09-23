package GlobalHandler

import (
	"Engine-AntiGinx/App/Errors"
	HttpClient "Engine-AntiGinx/App/HTTP"
	"Engine-AntiGinx/App/Reporter"
	"Engine-AntiGinx/App/Runner"
	parameterparser "Engine-AntiGinx/App/parser"
	"encoding/json"
	"fmt"
	"os"
)

// ErrorHandler serves as the global safety net and execution controller for the application.
type ErrorHandler struct {
	cliMode bool
}

// InitializeErrorHandler creates a new instance of the global error handler.
func InitializeErrorHandler(cliMode bool) *ErrorHandler {
	return &ErrorHandler{
		cliMode: cliMode,
	}
}

// RunSafe executes the main application flow within a protected scope.
func (e *ErrorHandler) RunSafe() {
	defer func() {
		if r := recover(); r != nil {
			switch val := r.(type) {
			case Errors.Error:
				e.printError(val)
			case HttpClient.HttpError:
				// Convert specific HTTP error to generic App Error
				err := Errors.Error{
					Code:        val.Code,
					Message:     val.Message,
					Source:      "Http Client",
					IsRetryable: val.IsRetryable,
				}
				e.printError(err)
			default:
				// Catch-all for runtime panics (e.g. nil pointer dereference)
				err := Errors.Error{
					Code:        999,
					Message:     fmt.Sprintf("Panic: %v", val),
					Source:      "Runtime/Critical",
					IsRetryable: false,
				}
				e.printError(err)
			}
			os.Exit(1)
		}
	}()
	args := os.Args
	resolver := parameterparser.CreateResolver()
	parser, formatter := resolver.Resolve(args)
	parsedParams := parser.Parse(args)
	execPlan := formatter.FormatParameters(parsedParams)
	runner := Runner.CreateJobRunner()
	repResolver := Reporter.NewResolver()
	runner.Orchestrate(execPlan, repResolver)
}

// printError writes the formatted error details to standard error (os.Stderr).
func (e *ErrorHandler) printError(err Errors.Error) {
	if e.cliMode {
		_, _ = fmt.Fprintf(os.Stderr, `
--------------------------------------------------
ERROR SOURCE: %s
EXIT CODE:    %d
MESSAGE:      %s
RETRYABLE:    %t
--------------------------------------------------
`, err.Source, err.Code, err.Message, err.IsRetryable)
	} else {
		encoder := json.NewEncoder(os.Stderr)
		encoder.SetIndent("", "  ")
		if encodeErr := encoder.Encode(err); encodeErr != nil {
			_, _ = fmt.Fprintf(os.Stderr, "FATAL: Failed to encode error to JSON: %v\n Original Error: %s\n", encodeErr, err.Message)
		}
	}
}
