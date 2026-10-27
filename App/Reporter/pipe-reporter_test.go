package Reporter

import (
	"Engine-AntiGinx/App/Metrics"
	"Engine-AntiGinx/App/Reporter/types"
	"Engine-AntiGinx/App/SiteTests"
	"Engine-AntiGinx/App/execution/strategy"
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInitializePipeReporter(t *testing.T) {
	resChan := make(chan strategy.ResultWrapper)
	logChan := make(chan types.LogEvent)
	metChan := make(chan Metrics.MetricsEvent)

	reporter := InitializePipeReporter(resChan, "test-target", "task-123", logChan, metChan)

	assert.NotNil(t, reporter)
	assert.Equal(t, "test-target", reporter.target)
	assert.Equal(t, "task-123", reporter.testId)
	assert.Equal(t, resChan, reporter.resultChannel)
	assert.Equal(t, logChan, reporter.logChan)
	assert.Equal(t, metChan, reporter.metricsChan)
}

func TestPipeReporter_PrepareResult(t *testing.T) {
	reporter := &PipeReporter{}

	t.Run("Valid TestResult", func(t *testing.T) {
		testRes := &SiteTests.TestResult{Name: "test1"}
		wrapper := strategy.WrapStrategyResult(testRes, nil, nil)

		res := reporter.prepareResult(wrapper, "target.com", "t-1")

		assert.NotNil(t, res)
		assert.Equal(t, "target.com", res.Target)
		assert.Equal(t, "t-1", res.TestId)
		assert.Equal(t, types.Success, res.ResultType)
		assert.False(t, res.EndFlag)
		assert.Equal(t, "test1", res.Result.Name)
	})

	t.Run("Valid RequestInfo", func(t *testing.T) {
		reqInfo := &strategy.RequestInfo{Message: "info"}
		wrapper := strategy.WrapStrategyResult(nil, nil, reqInfo)

		res := reporter.prepareResult(wrapper, "target.com", "t-1")

		assert.NotNil(t, res)
		assert.Equal(t, types.Message, res.ResultType)
		assert.Equal(t, "info", res.ProcessInfo.Message)
	})

	t.Run("Empty Wrapper", func(t *testing.T) {
		wrapper := strategy.WrapStrategyResult(nil, nil, nil)
		res := reporter.prepareResult(wrapper, "target.com", "t-1")
		assert.Nil(t, res)
	})
}

func TestPipeReporter_PrepareEvents(t *testing.T) {
	reporter := &PipeReporter{target: "target.com", testId: "t-1"}

	t.Run("Prepare LogEvent", func(t *testing.T) {
		logEv := types.LogEvent{Message: "test log", Level: slog.LevelInfo}
		wrapper := reporter.prepareLogEvent(logEv)

		assert.NotNil(t, wrapper)
		assert.Equal(t, types.Log, wrapper.EventType)

		var parsedLog types.LogEvent
		err := json.Unmarshal(wrapper.Event, &parsedLog)
		assert.NoError(t, err)
		assert.Equal(t, "test log", parsedLog.Message)
	})

	t.Run("Prepare MetricEvent", func(t *testing.T) {
		metEv := Metrics.MetricsEvent{Name: "test_metric", Value: 1.5}
		wrapper := reporter.prepareMetricEvent(metEv)

		assert.NotNil(t, wrapper)
		assert.Equal(t, types.Metrics, wrapper.EventType)

		var parsedMetric Metrics.MetricsEvent
		err := json.Unmarshal(wrapper.Event, &parsedMetric)
		assert.NoError(t, err)
		assert.Equal(t, "test_metric", parsedMetric.Name)
		assert.Equal(t, 1.5, parsedMetric.Value)
	})

	t.Run("Prepare EndMessage", func(t *testing.T) {
		wrapper := reporter.prepareEndMessage()

		assert.NotNil(t, wrapper)
		assert.Equal(t, types.Result, wrapper.EventType)

		var parsedRes struct {
			Target  string `json:"target"`
			EndFlag bool   `json:"endFlag"`
		}
		err := json.Unmarshal(wrapper.Event, &parsedRes)
		assert.NoError(t, err)
		assert.True(t, parsedRes.EndFlag)
		assert.Equal(t, "target.com", parsedRes.Target)
	})
}

func TestPipeReporter_StartListening(t *testing.T) {
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	defer func() { os.Stdout = oldStdout }()

	resChan := make(chan strategy.ResultWrapper, 5)
	logChan := make(chan types.LogEvent, 5)
	metChan := make(chan Metrics.MetricsEvent, 5)

	reporter := InitializePipeReporter(resChan, "target.com", "t-1", logChan, metChan)
	done := reporter.StartListening()

	testRes := &SiteTests.TestResult{Name: "test1"}
	resChan <- strategy.WrapStrategyResult(testRes, nil, nil)
	logChan <- types.LogEvent{Message: "log_test"}
	metChan <- Metrics.MetricsEvent{Name: "metric_test"}

	resChan <- strategy.WrapStrategyResult(nil, nil, nil)

	close(resChan)
	close(logChan)
	close(metChan)

	failedUploads := <-done

	assert.Equal(t, 1, failedUploads)

	assert.NoError(t, w.Close())
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	output := buf.String()

	assert.Contains(t, output, "test1")
	assert.Contains(t, output, "log_test")
	assert.Contains(t, output, "metric_test")
	assert.Contains(t, output, `"endFlag":true`)
}
