package Tests

import (
	"Engine-AntiGinx/App/Errors"
	"encoding/json"
	"fmt"
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
	Name        string      `json:"Name"`
	Certainty   int         `json:"Certainty"` // percentage certainty of the result
	ThreatLevel ThreatLevel `json:"ThreatLevel"`
	Metadata    any         `json:"Metadata"`
	Description string      `json:"Description"`
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

// String() method to print out text representation o ThreadLevel
func (t ThreatLevel) String() string {
	switch t {
	case None:
		return "None"
	case Info:
		return "Info"
	case Low:
		return "Low"
	case Medium:
		return "Medium"
	case High:
		return "High"
	case Critical:
		return "Critical"
	default:
		panic(Errors.Error{
			Message: fmt.Sprintf("Unknown Threat Level %d", t),
		})
	}
}

// MarshalJSON method is a helper method to properly serialize ThreatLevel into json
func (t ThreatLevel) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.String())
}
