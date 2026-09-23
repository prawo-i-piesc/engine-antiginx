package execution

import "Engine-AntiGinx/App/execution/strategy"

// Plan represents a complete blueprint for a security scanning task.
type Plan struct {
	Target      string
	AntiBotFlag bool
	Strategies  []strategy.TestStrategy
	Contexts    map[string]strategy.TestContext
	TaskId      string
	IsHelp      bool
}
