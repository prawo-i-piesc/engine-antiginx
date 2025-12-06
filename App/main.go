// Package main provides the entry point for the Engine-AntiGinx security scanner
// command-line application.
//
// This application performs security assessments on web targets by executing
// various security tests including HTTPS verification, HSTS analysis, and
// server header information disclosure detection.
//
// Usage:
//
//	engine-antiginx test --target <url> --tests <test_ids...>
//
// Example:
//
//	# Run HTTPS and HSTS tests on example.com
//	engine-antiginx test --target example.com --tests https hsts
//
//	# Run all available tests
//	engine-antiginx test --target example.com --tests https hsts serv-h-a
//
// Available Tests:
//   - https: Verifies HTTPS protocol usage
//   - hsts: Analyzes HTTP Strict Transport Security headers
//   - serv-h-a: Server header analysis for information disclosure
//
// The application follows a modular architecture:
//  1. Parameter Parser: Extracts command-line arguments
//  2. Job Runner: Orchestrates test execution
//  3. Test Registry: Provides access to available security tests
//  4. Reporter: Outputs results to CLI or backend API
package main

import (
	Parameter_Parser "Engine-AntiGinx/App/Parameter-Parser"
	"Engine-AntiGinx/App/Runner"
	"os"
)

// main is the entry point of the Engine-AntiGinx security scanner.
// It initializes the parameter parser, processes command-line arguments,
// and delegates test execution to the job runner.
//
// The execution flow:
//  1. Create a command parser instance
//  2. Parse os.Args to extract target URL and test IDs
//  3. Create a job runner instance
//  4. Orchestrate the security tests based on parsed parameters
//
// Exit behavior:
//   - Exits with code 0 on successful completion
//   - Panics with structured error on invalid parameters or test failures
func main() {
	parser := Parameter_Parser.CreateCommandParser()
	parsedParams := parser.Parse(os.Args)
	runner := Runner.CreateJobRunner()
	runner.Orchestrate(parsedParams)
}
