package main

import (
	Parameter_Parser "Engine-AntiGinx/App/Parameter-Parser"
	"Engine-AntiGinx/App/Runner"
	"os"
)

func main() {
	/*
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
	*/
	parser := Parameter_Parser.CreateCommandParser()
	parsedParams := parser.Parse(os.Args)
	runner := Runner.CreateJobRunner()
	runner.Orchestrate(parsedParams)
}
