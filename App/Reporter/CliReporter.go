// Package Reporter provides result consumers.
package Reporter

import (
	"Engine-AntiGinx/App/Errors"
	"Engine-AntiGinx/App/SiteTests"
	"Engine-AntiGinx/App/execution/strategy"
	"fmt"
)

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

var separator string = `---------------------------------------------`

// cliReporter prints results to stdout.
type cliReporter struct {
	resultChannel <-chan strategy.ResultWrapper
}

// InitializeCliReporter constructs a console reporter for the given channel.
func InitializeCliReporter(channel chan strategy.ResultWrapper) *cliReporter {
	return &cliReporter{
		resultChannel: channel,
	}
}

// StartListening consumes results until the input channel closes.
func (c *cliReporter) StartListening() <-chan int {
	done := make(chan int)
	go func() {
		fmt.Println(banner)
		fmt.Println("TEST RESULT")

		// The loop terminates automatically when c.resultChannel is closed by the sender.
		for result := range c.resultChannel {
			ok, val := result.GetTestResult()
			okInfo, info := result.GetReqInfo()
			if !ok && !okInfo {
				panic(Errors.Error{
					Code: 100,
					Message: `Cli Reporter error occurred. This could be due to:
								- fatal error`,
					Source:      "Cli Reporter",
					IsRetryable: false,
				})
			}
			if okInfo {
				printProcessInfo(*info)
			} else {
				printTestResult(*val)
			}
		}

		// Signal completion. 0 indicates success (no upload errors in CLI mode).
		done <- 0
	}()
	return done
}

// printTestResult writes one result to stdout.
func printTestResult(result SiteTests.TestResult) {
	fmt.Printf("Test name: %s\n", result.Name)
	fmt.Printf("Certanity: %d\n", result.Certainty)
	fmt.Printf("Threat level %v\n", result.ThreatLevel)
	fmt.Printf("Description: %s\n", result.Description)
	fmt.Println(separator)
}

func printProcessInfo(info strategy.RequestInfo) {
	// The wording stops short of "unable to test this website": a failed request now only
	// costs the tests that need the page content, while the pre-response and structure
	// phases have already reported their findings above.
	fmt.Printf("Engine was unable to load this website's content\n")
	fmt.Printf("\nTest process message: \n%s\n", info.Message)
	fmt.Println(separator)
}
