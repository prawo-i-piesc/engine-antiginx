package Errors

// Error struct for clarification of error handling across engine
type Error struct {
	Code    int
	Message string
	Source  string
}
