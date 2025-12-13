package GlobalHandler

import (
	"Engine-AntiGinx/App/Errors"
	HttpClient "Engine-AntiGinx/App/HTTP"
	Parameter_Parser "Engine-AntiGinx/App/Parameter-Parser"
	"Engine-AntiGinx/App/Runner"
	"encoding/json"
	"fmt"
	"os"
)

// ErrorHandler serves as the global safety net and execution controller for the application.
// It is responsible for wrapping the main application logic within a panic-recovery boundary
// and formatting any resulting errors according to the selected output mode (CLI or JSON).
type ErrorHandler struct {
	cliMode bool
}

// InitializeErrorHandler creates a new instance of the global error handler.
//
// It configures the reporting mode based on the cliMode flag. This instance is intended
// to be used at the very top level of the application (typically in main.go) to ensure
// all unhandled panics are caught and reported gracefully.
//
// Parameters:
//   - cliMode: If true, errors are printed in a human-readable text block.
//     If false, errors are printed as structured JSON objects for machine consumption.
//
// Returns:
//   - *ErrorHandler: A pointer to the configured handler instance ready to execute RunSafe().
func InitializeErrorHandler(cliMode bool) *ErrorHandler {
	return &ErrorHandler{
		cliMode: cliMode,
	}
}

// RunSafe executes the main application flow within a protected scope.
// This is the entry point for the business logic, triggering argument parsing
// and job orchestration.
//
// The function establishes a defer/recover block to intercept any panics that occur
// during execution. It acts as a "try-catch" mechanism for the entire process,
// ensuring that the application never crashes with a raw stack trace but instead
// exits with a controlled error message and status code.
//
// Panic Recovery Strategy:
//   - Errors.Error: Handled directly, preserving the original code and message.
//   - HttpClient.HttpError: Converted to a generic Errors.Error with "Http Client" source.
//   - default (runtime panics): Wrapped in a critical Errors.Error (code 999) with stack details.
//
// Execution Flow:
//  1. Sets up panic recovery.
//  2. Creates and runs the CommandParser to process os.Args.
//  3. Creates and runs the JobRunner to execute the scanning logic.
//  4. If a panic occurs, it is caught, printed to Stderr, and the process exits with code 1.
//
// Exit Behavior:
//   - On Success: The function returns normally (exit code 0).
//   - On Panic: The process terminates immediately with os.Exit(1).
//
// Example:
//
//	handler := GlobalHandler.InitializeErrorHandler(true)
//	// Will run the app and print pretty errors to stderr if something explodes
//	handler.RunSafe()
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
	parser := Parameter_Parser.CreateCommandParser()
	parsedParams := parser.Parse(os.Args)
	runner := Runner.CreateJobRunner()
	runner.Orchestrate(parsedParams)
}

// printError writes the formatted error details to standard error (os.Stderr).
//
// The format is determined by the cliMode flag set during initialization.
// This abstraction allows the application to be used both by humans in a terminal
// and by automated workers/wrappers expecting JSON.
//
// Output Formats:
//   - CLI Mode (true): A visual, ASCII-formatted block containing Source, Exit Code,
//     Message, and Retryable status.
//   - JSON Mode (false): A strict JSON object representing the Error struct.
//
// Parameters:
//   - err: The standardized Errors.Error object to display.
func (e *ErrorHandler) printError(err Errors.Error) {
	if e.cliMode {
		fmt.Fprintf(os.Stderr, `
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
		encoder.Encode(err)
	}
}
