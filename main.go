package main

import (
	//ParameterParser "Engine-AntiGinx/App/Parameter-Parser"
	HttpClient "Engine-AntiGinx/App/HTTP"
	Tests "Engine-AntiGinx/App/Tests"
	"fmt"
	//"os"
)

func main() {
	/*
		parser := ParameterParser.CreateCommandParser()
		fmt.Println(parser.Parse(os.Args))
	*/

	// Create HTTP client
	httpClient := HttpClient.CreateHttpWrapper(HttpClient.WithHeaders(map[string]string{
		"User-Agent": "CustomAgent/1.0",
	}))

	testWebsite := "http://startrinity.com/HttpTester/HttpRestApiClientTester.aspx"

	// Make HTTP request
	result := httpClient.Get(testWebsite, HttpClient.WithHeaders(map[string]string{
		"User-Agent": "AntiGinx-TestClient/1.0",
	}))

	fmt.Printf("HTTP Response Status: %s\n", result.Status)
	fmt.Println("---")

	httpsTest := Tests.NewHTTPSTest()
	testParams := Tests.ResponseTestParams{Response: result}
	testResult := httpsTest.Run(testParams)

	fmt.Printf("Test ID: %s\n", httpsTest.GetId())
	fmt.Printf("Test Name: %s\n", httpsTest.GetName())
	fmt.Printf("Test Description: %s\n", httpsTest.GetDescription())
	fmt.Println("---")

	fmt.Printf("Result Name: %s\n", testResult.Name)
	fmt.Printf("Certainty: %d%%\n", testResult.Certainty)
	fmt.Printf("Threat Level: %v\n", testResult.ThreatLevel)
	fmt.Printf("Description: %s\n", testResult.Description)

}
