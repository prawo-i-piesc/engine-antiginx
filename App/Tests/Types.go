package Tests

import (
	"net/http"
)

type ThreatLevel int

const (
	None ThreatLevel = iota
	Info
	Low
	Medium
	High
	Critical
)

// TestResult represents the result of a test, including its name, certainty, threat level, metadata, and description.
type TestResult struct {
	Name        string
	Certainty   int // percentage certainty of the result
	ThreatLevel ThreatLevel
	Metadata    any
	Description string
}

// ResponseTestParams contains parameters for a response test, including the HTTP response to be tested.
type ResponseTestParams struct {
	Response *http.Response
}

// ResponseTest defines a test that operates on an HTTP response and returns a TestResult.
type ResponseTest struct {
	Id          string
	Name        string
	Description string

	RunTest func(params ResponseTestParams) TestResult
}

func (brt *ResponseTest) GetId() string          { return brt.Id }
func (brt *ResponseTest) GetName() string        { return brt.Name }
func (brt *ResponseTest) GetDescription() string { return brt.Description }

func (rt *ResponseTest) Run(params ResponseTestParams) TestResult {
	if rt.RunTest == nil {
		panic("Run method not implemented")
	}
	return rt.RunTest(params)
}
