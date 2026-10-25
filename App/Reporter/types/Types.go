package types

import (
	"Engine-AntiGinx/App/SiteTests"
	"Engine-AntiGinx/App/execution/strategy"
	"encoding/json"
	"fmt"
	"log/slog"
)

type EngineEventType int

const (
	Result EngineEventType = iota
	Log
	Metrics
	Error
)

type EngineEventWrapper struct {
	EventType EngineEventType
	Event     json.RawMessage
}

type ResultType string

const (
	Message ResultType = "Message"
	Success ResultType = "Success"
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

func (r TestResultWrapper) String() string {
	return fmt.Sprintf(
		"TestResultWrapper{Target:%q, TestId:%q, Result:%+v, EndFlag:%t, ResultType:%q, ProcessInfo:%+v}",
		r.Target,
		r.TestId,
		r.Result,
		r.EndFlag,
		r.ResultType,
		r.ProcessInfo,
	)
}

type LogEvent struct {
	Message string     `json:"Message"`
	TestId  string     `json:"TestId"`
	Level   slog.Level `json:"Level"`
	Error   string     `json:"Error"`
	Event   string     `json:"Event"`
}

type ErrorEvent struct {
	Message string `json:"Message"`
	Error   error  `json:"Error"`
	Code    int    `json:"Code"`
}
