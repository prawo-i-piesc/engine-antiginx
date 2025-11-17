package main

import (
	//ParameterParser "Engine-AntiGinx/App/Parameter-Parser"
	HttpClient "Engine-AntiGinx/App/HTTP"
	"fmt"
	//"os"
)

func main() {
	/*
		parser := ParameterParser.CreateCommandParser()
		fmt.Println(parser.Parse(os.Args))
	*/

	httpClient := HttpClient.CreateHttpWrapper(HttpClient.WithHeaders(map[string]string{
		"User-Agent": "CustomAgent/1.0",
	}))

	result := httpClient.Get("https://duckduckgo.com/?q=thinking+monkey&ia=images&iax=images&iai=https%3A%2F%2Fwww.itl.cat%2Fpngfile%2Fbig%2F22-221926_thinking-cute-monkey.jpg", HttpClient.WithHeaders(map[string]string{
		"User-Agent": "CustomAgent/2.0",
	}))

	fmt.Println(result.Status)

}
