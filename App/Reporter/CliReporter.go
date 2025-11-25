// Package Reporter provides multiple reporting implementations for test results.
// This file contains the CLI reporter which outputs formatted test results directly
// to the console (stdout) for local debugging and interactive usage.
//
// The CLI reporter is used when no backend URL is configured or when running
// the scanner in standalone/development mode. It provides human-readable output
// with visual formatting including ASCII art banner and result separators.
package Reporter

import (
	"Engine-AntiGinx/App/Tests"
	"fmt"
)

// banner is the ASCII art logo displayed at the start of CLI reporting.
// It identifies the application as "ANTIGINX ENGINE" and is printed once
// when the reporter starts listening for results.
var banner string = `
    _    _   _ _____ ___ ____ ___ _   _ _  __
   / \  | \ | |_   _|_ _/ ___|_ _| \ | \ \/ /
  / _ \ |  \| | | |  | | |  _ | ||  \| |\  / 
 / ___ \| |\  | | |  | | |_| || || |\  |/  \ 
/_/   \_\_| \_| |_| |___\____|___|_| \_/_/\_\
 _____ _   _  ____ ___ _   _ _____ 
| ____| \ | |/ ___|_ _| \ | | ____|
|  _| |  \| | |  _ | ||  \| |  _|  
| |___| |\  | |_| || || |\  | |___ 
|_____|_| \_|\____|___|_| \_|_____|
`

// separator is a visual delimiter printed between test results in the console output.
// It helps distinguish individual test results and improves readability of the output
// when multiple tests are executed.
var separator string = `---------------------------------------------`

// cliReporter is a console-based reporter implementation that outputs test results
// directly to standard output (stdout). It provides formatted, human-readable output
// for interactive use and local development.
//
// Unlike the backendReporter, this implementation does not perform HTTP requests
// or implement retry logic. It simply formats and prints results synchronously
// as they arrive on the result channel.
//
// The reporter is typically used in scenarios:
//   - Local development and debugging
//   - Standalone scanner execution without backend
//   - Manual security testing and verification
//   - CI/CD pipelines that need console output
//
// Fields:
//   - resultChannel: Receive-only channel for consuming test results
type cliReporter struct {
	resultChannel <-chan Tests.TestResult
}

// InitializeCliReporter creates and returns a new instance of the CLI reporter
// configured to consume test results from the specified channel. The reporter
// is ready to start listening immediately after initialization.
//
// This factory function provides a simple way to create a CLI reporter for scenarios
// where HTTP backend reporting is not required or desired. It's commonly used for:
//   - Local development and testing
//   - Debugging security tests
//   - Standalone scanner execution
//   - Quick security assessments
//
// The reporter will format and print each result to stdout as it's received,
// providing immediate feedback during test execution.
//
// Parameters:
//   - channel: The input channel where test results are published by the Runner
//
// Returns:
//   - *cliReporter: Configured reporter instance ready to start listening
//
// Example:
//
//	resultChan := make(chan Tests.TestResult, 10)
//	reporter := InitializeCliReporter(resultChan)
//	doneChan := reporter.StartListening()
//
//	// Send test results...
//	for _, result := range testResults {
//	    resultChan <- result
//	}
//	close(resultChan)
//
//	// Wait for completion
//	<-doneChan
func InitializeCliReporter(channel chan Tests.TestResult) *cliReporter {
	return &cliReporter{
		resultChannel: channel,
	}
}

// StartListening begins the asynchronous process of consuming and printing test results
// to the console. This method spawns a goroutine that displays the application banner
// and then continuously processes results until the input channel is closed.
//
// Processing sequence:
//  1. Print ASCII art banner to stdout
//  2. Print "TEST RESULT" header
//  3. Enter processing loop (range over resultChannel)
//  4. For each result: call printTestResult to format and display
//  5. When channel closes: send completion signal and exit
//
// Output format for each test:
//   - Test Name
//   - Certainty percentage (0-100)
//   - Threat Level (0-5: None, Info, Low, Medium, High, Critical)
//   - Description
//   - Visual separator line
//
// The method provides immediate visual feedback as tests complete, making it ideal
// for interactive use and debugging. Unlike the backend reporter, this implementation
// is synchronous (no retries) and has no failure modes - all results are printed.
//
// Returns:
//   - <-chan int: Read-only channel that receives 0 when processing is complete
//     (always 0 for CLI reporter as there are no upload failures)
//
// Example:
//
//	reporter := InitializeCliReporter(resultChan)
//	doneChan := reporter.StartListening()
//
//	// Results are printed as they arrive...
//	// Output:
//	// [ASCII Banner]
//	// TEST RESULT
//	// Test name: HTTPS Protocol Verification
//	// Certainty: 100
//	// Threat level: 0
//	// Description: Connection is secured with HTTPS protocol
//	// ---------------------------------------------
//
//	<-doneChan  // Blocks until all results processed
func (c *cliReporter) StartListening() <-chan int {
	done := make(chan int)
	go func() {
		fmt.Println(banner)
		fmt.Println("TEST RESULT")

		// The loop terminates automatically when c.resultChannel is closed by the sender.
		for result := range c.resultChannel {
			printTestResult(result)
		}

		// Signal completion. 0 indicates success (no upload errors in CLI mode).
		done <- 0
	}()
	return done
}

// printTestResult formats and prints a single test result to stdout with structured formatting.
// This helper function provides consistent, human-readable output for all test results.
//
// Output format:
//   - Test name: [string] - The human-readable name of the test
//   - Certainty: [0-100] - Confidence percentage in the result
//   - Threat level: [0-5] - Security threat classification
//   - 0 = None (no issues)
//   - 1 = Info (informational)
//   - 2 = Low (minor issues)
//   - 3 = Medium (moderate concern)
//   - 4 = High (serious vulnerability)
//   - 5 = Critical (severe vulnerability)
//   - Description: [string] - Detailed explanation of the finding
//   - Separator line for visual distinction
//
// The function is called internally by StartListening for each result received
// from the result channel.
//
// Parameters:
//   - result: The TestResult structure containing test execution data
//
// Example output:
//
//	Test name: HTTPS Protocol Verification
//	Certainty: 100
//	Threat level: 4
//	Description: Connection uses insecure HTTP protocol - data is transmitted in plaintext
//	---------------------------------------------
func printTestResult(result Tests.TestResult) {
	fmt.Printf("Test name: %s\n", result.Name)
	fmt.Printf("Certanity: %d\n", result.Certainty)
	fmt.Printf("Threat level %v\n", result.ThreatLevel)
	fmt.Printf("Description: %s\n", result.Description)
	fmt.Println(separator)
}
