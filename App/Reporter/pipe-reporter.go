package Reporter

import (
	"Engine-AntiGinx/App/Metrics"
	"Engine-AntiGinx/App/Reporter/types"
	"Engine-AntiGinx/App/SiteTests"
	"Engine-AntiGinx/App/execution/strategy"
	"encoding/json"
	"log/slog"
	"os"
)

type PipeReporter struct {
	resultChannel chan strategy.ResultWrapper
	logChan       chan types.LogEvent
	metricsChan   chan Metrics.MetricsEvent
	testId        string
	target        string
}

func InitializePipeReporter(resultChannel chan strategy.ResultWrapper, target string, testId string, logChan chan types.LogEvent, metricsChan chan Metrics.MetricsEvent) *PipeReporter {
	return &PipeReporter{
		resultChannel: resultChannel,
		logChan:       logChan,
		metricsChan:   metricsChan,
		testId:        testId,
		target:        target,
	}
}

func (p *PipeReporter) StartListening() <-chan int {
	done := make(chan int)

	go func() {
		failedUploads := 0
		encoder := json.NewEncoder(os.Stdout)

		for p.resultChannel != nil || p.logChan != nil || p.metricsChan != nil {
			var eventWrapper *types.EngineEventWrapper
			select {
			case result, ok := <-p.resultChannel:
				if !ok {
					p.resultChannel = nil
					continue
				}

				resultWrapper := p.prepareResult(result, p.target, p.testId)

				if resultWrapper == nil {
					slog.Warn("Invalid event (skipped)",
						slog.Any("Event", result))
					failedUploads++
					continue
				}

				rawJson, err := json.Marshal(resultWrapper)
				if err != nil {
					slog.Warn("Cannot serialize result event (skipped)",
						slog.Any("Event", resultWrapper),
						slog.String("Error", err.Error()))
					failedUploads++
					continue
				}

				eventWrapper = &types.EngineEventWrapper{
					EventType: types.Result,
					Event:     rawJson,
				}

			case log, ok := <-p.logChan:
				if !ok {
					p.logChan = nil
					continue
				}

				eventWrapper = p.prepareLogEvent(log)
				if eventWrapper == nil {
					failedUploads++
					continue
				}

			case metric, ok := <-p.metricsChan:
				if !ok {
					p.metricsChan = nil
					continue
				}

				eventWrapper = p.prepareMetricEvent(metric)
				if eventWrapper == nil {
					failedUploads++
					continue
				}
			}
			if err := encoder.Encode(eventWrapper); err != nil {
				failedUploads++
			}
		}

		if eventWrapper := p.prepareEndMessage(); eventWrapper != nil {
			if err := encoder.Encode(eventWrapper); err != nil {
				failedUploads++
			}
		}

		done <- failedUploads
		close(done)
	}()

	return done
}

func (p *PipeReporter) prepareMetricEvent(metric Metrics.MetricsEvent) *types.EngineEventWrapper {
	rawJson, err := json.Marshal(metric)
	if err != nil {
		slog.Warn("Cannot serialize metric event (skipped)",
			slog.Any("Event", metric),
			slog.String("Error", err.Error()))
		return nil
	}
	eventWrapper := &types.EngineEventWrapper{
		EventType: types.Metrics,
		Event:     rawJson,
	}
	return eventWrapper
}
func (p *PipeReporter) prepareLogEvent(log types.LogEvent) *types.EngineEventWrapper {
	rawJson, err := json.Marshal(log)
	if err != nil {
		slog.Warn("Cannot serialize log event (skipped)",
			slog.String("Error", err.Error()))
		return nil
	}

	eventWrapper := &types.EngineEventWrapper{
		EventType: types.Log,
		Event:     rawJson,
	}
	return eventWrapper
}

func (p *PipeReporter) prepareEndMessage() *types.EngineEventWrapper {
	endEvent := types.TestResultWrapper{
		Target:      p.target,
		TestId:      p.testId,
		Result:      SiteTests.TestResult{},
		EndFlag:     true,
		ResultType:  types.Message,
		ProcessInfo: strategy.RequestInfo{},
	}

	rawJson, err := json.Marshal(endEvent)
	if err != nil {
		slog.Warn("Cannot serialize end event (skipped)",
			slog.Any("Event", endEvent),
			slog.String("Error", err.Error()))
		return nil
	}
	eventWrapper := &types.EngineEventWrapper{
		EventType: types.Result,
		Event:     rawJson,
	}
	return eventWrapper
}
func (p *PipeReporter) prepareResult(result strategy.ResultWrapper, target string, testId string) *types.TestResultWrapper {
	if exists, val := result.GetReqInfo(); exists {
		return &types.TestResultWrapper{
			Target:      target,
			TestId:      testId,
			Result:      SiteTests.TestResult{},
			EndFlag:     false,
			ResultType:  types.Message,
			ProcessInfo: *val,
		}
	} else if exists, val := result.GetTestResult(); exists {
		return &types.TestResultWrapper{
			Target:      target,
			TestId:      testId,
			Result:      *val,
			EndFlag:     false,
			ResultType:  types.Success,
			ProcessInfo: strategy.RequestInfo{},
		}
	}
	return nil
}
