package Reporter

import (
	"Engine-AntiGinx/App/Errors"
	"Engine-AntiGinx/App/execution/strategy"
	"fmt"
)

var helpBanner = `
    _    _   _ _____ ___ ____ ___ _   _ _  __   _   _ _____ _     ____  
   / \  | \ | |_   _|_ _/ ___|_ _| \ | \ \/ /  | | | | ____| |   |  _ \ 
  / _ \ |  \| | | |  | | |  _ | ||  \| |\  /   | |_| |  _| | |   | |_) |
 / ___ \| |\  | | |  | | |_| || || |\  |/  \   |  _  | |___| |___|  __/ 
/_/   \_\_| \_| |_| |___\____|___|_| \_/_/\_\  |_| |_|_____|_____|_|  
`

type helpReporter struct {
	resultChan chan strategy.ResultWrapper
}

func NewHelpReporter(resultChan chan strategy.ResultWrapper) *helpReporter {
	return &helpReporter{
		resultChan: resultChan,
	}
}

func (hr *helpReporter) StartListening() <-chan int {
	done := make(chan int, 1)
	go func() {
		fmt.Println(helpBanner)

		for result := range hr.resultChan {
			ok, helpMess := result.GetHelpMessage()
			if !ok {
				panic(Errors.Error{
					Code: 100,
					Message: `Help Reporter error occurred. This could be due to:
								- Nil help message`,
					Source:      "Help Reporter",
					IsRetryable: false,
				})
			}
			hr.printHelpInstruction(*helpMess)
		}
		done <- 0
	}()
	return done
}
func (hr *helpReporter) printHelpInstruction(helpInstruction strategy.HelpStrategyResult) {
	sectionArray := helpInstruction.GetSectionArray()
	fmt.Printf("%s\n", helpInstruction.GetHelpHeader())
	fmt.Printf("%s\n", separator)
	for i := 0; i < len(sectionArray); i++ {
		currSection := sectionArray[i]
		fmt.Printf("%s\n", currSection.SectionName)
		fmt.Printf("%s\n", currSection.SectionData)
		fmt.Printf("%s\n", separator)
	}
}
