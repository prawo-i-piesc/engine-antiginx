package Reporter

import (
	"Engine-AntiGinx/App/Tests"
	"fmt"
)

// banner displays the application ASCII art logo.
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

// separator is used to visually deliminate distinct test results in the console output.
var separator string = `---------------------------------------------`

// cliReporter is an implementation of the Reporter interface that outputs
// test results directly to the standard console output (stdout).
type cliReporter struct {
	resultChannel <-chan Tests.TestResult
}

// InitializeCliReporter creates and returns a new instance of the CLI reporter.
//
// It configures the reporter to consume test results from the provided channel.
// This reporter is typically used when no backend URL is configured or for local debugging.
func InitializeCliReporter(channel chan Tests.TestResult) *cliReporter {
	return &cliReporter{
		resultChannel: channel,
	}
}

// StartListening begins the asynchronous process of consuming and printing test results.
//
// It performs the following actions:
//  1. Prints the application banner to stdout.
//  2. Starts a background goroutine to iterate over the result channel.
//  3. Formats and prints each received TestResult using printTestResult.
//  4. Sends a signal (0) to the returned channel when the input channel is closed
//     and all processing is complete.
//
// The returned channel allows the caller to block until reporting is finished.
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

// printTestResult formats the details of a single test result and writes them to stdout.
//
// It displays:
//   - Test Name
//   - Certainty percentage
//   - Threat Level
//   - Description
//   - A visual separator
func printTestResult(result Tests.TestResult) {
	fmt.Printf("Test name: %s\n", result.Name)
	fmt.Printf("Certanity: %d\n", result.Certainty)
	fmt.Printf("Threat level %v\n", result.ThreatLevel)
	fmt.Printf("Description: %s\n", result.Description)
	fmt.Println(separator)
}
