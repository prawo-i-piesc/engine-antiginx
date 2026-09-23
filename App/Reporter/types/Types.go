package types

import (
	"Engine-AntiGinx/App/SiteTests"
	"Engine-AntiGinx/App/execution/strategy"
)

type ResultType int

const (
	Message ResultType = iota
	Success
)

// TestResultWrapper is the JSON payload sent to the backend.
type TestResultWrapper struct {
	Target      string               `json:"target"`
	TestId      string               `json:"testId"`
	Result      SiteTests.TestResult `json:"result"`
	EndFlag     bool                 `json:"endFlag"`
	ResultType  ResultType           `json:"resultType"`
	ProcessInfo strategy.RequestInfo `json:"message"`
}
