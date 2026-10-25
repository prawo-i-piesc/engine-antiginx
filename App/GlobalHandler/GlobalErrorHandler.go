package GlobalHandler

import (
	"Engine-AntiGinx/App/Errors"
	HttpClient "Engine-AntiGinx/App/HTTP"
	"Engine-AntiGinx/App/Metrics"
	"Engine-AntiGinx/App/Reporter"
	"Engine-AntiGinx/App/Reporter/types"
	"Engine-AntiGinx/App/Runner"
	parameterparser "Engine-AntiGinx/App/parser"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"
)

const (
	logChannelSize     = 500
	metricsChannelSize = 100
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
			slog.Error("Critical panic recovered", slog.Any("error", r))
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

	metricsChannel := make(chan Metrics.MetricsEvent, metricsChannelSize)
	Metrics.SetChannel(metricsChannel)
	start := time.Now()
	defer func() {
		Metrics.ObserveScanDurationTime(time.Since(start).Seconds())
		close(metricsChannel)
	}()
	args := os.Args
	resolver := parameterparser.CreateResolver()
	parser, formatter := resolver.Resolve(args)
	parsedParams := parser.Parse(args)
	execPlan := formatter.FormatParameters(parsedParams)

	logChannel := make(chan types.LogEvent, logChannelSize)
	e.setupHandler(logChannel, execPlan.TaskId)
	slog.Info("AntiGinx Engine initialized", slog.String("taskId", execPlan.TaskId))

	runner := Runner.CreateJobRunner()
	repResolver := Reporter.NewResolver()
	runner.Orchestrate(execPlan, repResolver, logChannel, metricsChannel)
}

func (e *ErrorHandler) setupHandler(log chan<- types.LogEvent, taskId string) {
	var handler slog.Handler

	if _, exists := os.LookupEnv("PIPE_COMMUNICATION"); exists {
		handler = Reporter.NewLogHandler(log, taskId, slog.Level(-4))
	} else {
		handler = slog.NewTextHandler(io.Discard, nil)
	}

	slog.SetDefault(slog.New(handler))
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
