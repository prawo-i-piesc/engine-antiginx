package execution

import "Engine-AntiGinx/App/execution/strategy"

type Plan struct {
	Target      string
	AntiBotFlag bool
	Strategies  []strategy.TestStrategy
	Contexts    map[string]strategy.TestContext
	TaskId      string
}
