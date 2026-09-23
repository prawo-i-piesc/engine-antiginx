// Package Errors defines a structured application error.
package Errors

import "fmt"

// Error carries an error code, message, source and retry hint.
type Error struct {
	Code        int    `json:"Code"`
	Message     string `json:"Message"`
	Source      string `json:"Source"`
	IsRetryable bool   `json:"IsRetryable"`
}

// Error implements error, formatting the source, code, message and retry hint.
func (e *Error) Error() string {
	return fmt.Sprintf("[%s] Error %d: %s (Retryable: %t)", e.Source, e.Code, e.Message, e.IsRetryable)
}
