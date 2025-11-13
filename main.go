package main

import (
	ParameterParser "Engine-AntiGinx/App/Parameter-Parser"
	"fmt"
	"os"
)

func main() {
	parser := ParameterParser.CreateCommandParser()
	fmt.Println(parser.Parse(os.Args))
}
