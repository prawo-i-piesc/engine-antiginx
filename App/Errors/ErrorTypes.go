package Errors

import "fmt"

// Error struct for clarification of error handling across engine
type Error struct {
	Code        int
	Message     string
	Source      string
	IsRetryable bool
}

func (e *Error) Error() string {
	return fmt.Sprintf("[%s] Error %d: %s", e.Source, e.Code, e.Message, e.IsRetryable)
}
