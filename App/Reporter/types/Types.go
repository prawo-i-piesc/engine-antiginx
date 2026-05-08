package types

import (
	"Engine-AntiGinx/App/Tests"
	"Engine-AntiGinx/App/execution/strategy"
)

type ResultType int

const (
	Message ResultType = iota
	Success
)

// TestResultWrapper represents fully structured response sent to the backend
// Fields:
//   - Target: Given target
//   - TestId: id related to full scan
//   - Result: Core data of test
//   - EndFlag: Check if engine finished its job
type TestResultWrapper struct {
	Target      string               `json:"target"`
	TestId      string               `json:"testId"`
	Result      Tests.TestResult     `json:"result"`
	EndFlag     bool                 `json:"endFlag"`
	ResultType  ResultType           `json:"resultType"`
	ProcessInfo strategy.RequestInfo `json:"message"`
}
