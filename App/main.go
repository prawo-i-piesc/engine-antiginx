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
//  5. GlobalHandler: Reports errors to CLI or Queue Consumer
package main

import (
	"Engine-AntiGinx/App/GlobalHandler"
	"fmt"
	"os"

	"github.com/joho/godotenv"
)

// main is the entry point of the Engine-AntiGinx security scanner.
// It bootstraps the application by determining the execution mode (CLI vs. Backend)
// and initializing the global error handling mechanism.
//
// Mode Selection:
// The function checks for the existence of the "BACK_URL" environment variable:
//   - If PRESENT: Treats execution as a Backend Worker (cliMode = false).
//     Errors will be formatted as JSON for machine consumption.
//   - If ABSENT: Treats execution as a standalone CLI tool (cliMode = true).
//     Errors will be formatted as human-readable text blocks.
//
// Execution Flow:
//  1. Detect execution mode via os.LookupEnv("BACK_URL").
//  2. Initialize GlobalHandler with the calculated mode.
//  3. Delegate full control to errorHandler.RunSafe(), which encapsulates
//     argument parsing, job orchestration, and panic recovery.
func main() {
	err := godotenv.Load()
	if err != nil {
		fmt.Println("Cannot read .env file")
	}
	_, f := os.LookupEnv("BACK_URL")
	// If BACK_URL exists (f=true), we are in Backend mode (!f=false).
	// If BACK_URL is missing (f=false), we are in CLI mode (!f=true).
	errorHandler := GlobalHandler.InitializeErrorHandler(!f)
	errorHandler.RunSafe()
}
