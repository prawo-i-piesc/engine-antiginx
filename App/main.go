package main

import (
	Parameter_Parser "Engine-AntiGinx/App/Parameter-Parser"
	"Engine-AntiGinx/App/Runner"
	"os"
)

func main() {
	parser := Parameter_Parser.CreateCommandParser()
	parsedParams := parser.Parse(os.Args)
	runner := Runner.CreateJobRunner()
	runner.Orchestrate(parsedParams)
}
