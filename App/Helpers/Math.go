// Package helpers provides utility functions for common operations throughout the Engine-AntiGinx application.
// This file contains mathematical utility functions for numeric operations.
package helpers

// MinInt returns the smaller of two integers.
// This is a simple utility function for numeric comparison.
//
// Parameters:
//   - a: First integer
//   - b: Second integer
//
// Returns:
//   - int: The smaller of the two integers
//
// Example:
//
//	result := MinInt(5, 3)  // returns 3
//	result := MinInt(10, 15)  // returns 10
func MinInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
