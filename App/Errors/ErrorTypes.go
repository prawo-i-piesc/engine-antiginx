// Package Errors provides structured error handling with error codes and categorization
// for different failure scenarios across the Engine-AntiGinx application.
// It implements a panic-based error system with detailed error information including
// source tracking and retry capability indication.
package Errors

import "fmt"

// Error represents a structured error with additional context for debugging and error handling.
// It implements the standard error interface and provides rich error information including
// error codes, source component identification, and retry capability flags.
//
// The Error type is used throughout the application for consistent error reporting
// and includes the following categories by code ranges:
//   - 100-199: General and request creation errors
//   - 200-299: Network and response errors
//   - 300-399: Bot protection and security errors
//   - 400-499: Parsing and validation errors
//
// Fields:
//   - Code: Numeric error code for categorization and programmatic handling
//   - Message: Human-readable error description with context
//   - Source: Component or package name where the error originated
//   - IsRetryable: Indicates whether the operation can be safely retried
type Error struct {
	Code        int    `json:"Code"`
	Message     string `json:"Message"`
	Source      string `json:"Source"`
	IsRetryable bool   `json:"IsRetryable"`
}

// Error returns a formatted string representation of the error, implementing the error interface.
// The format includes the source component, error code, message, and retry capability.
//
// Returns:
//   - string: Formatted error message in the format "[Source] Error Code: Message (Retryable: bool)"
//
// Example output:
//
//	[HTTP] Error 101: Network timeout occurred (Retryable: true)
func (e *Error) Error() string {
	return fmt.Sprintf("[%s] Error %d: %s", e.Source, e.Code, e.Message, e.IsRetryable)
}
