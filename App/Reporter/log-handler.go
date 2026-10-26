package Reporter

import (
	"Engine-AntiGinx/App/Reporter/types"
	"context"
	"log/slog"
)

type LogHandler struct {
	logChan chan<- types.LogEvent
	testId  string
	level   slog.Level
}

func NewLogHandler(logChan chan<- types.LogEvent, testId string, level slog.Level) *LogHandler {
	return &LogHandler{
		logChan: logChan,
		testId:  testId,
		level:   level,
	}
}

func (h *LogHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level
}

func (h *LogHandler) Handle(_ context.Context, r slog.Record) error {
	var errObj error
	var eventObj string

	r.Attrs(func(a slog.Attr) bool {
		if a.Key == "error" || a.Key == "err" {
			if e, ok := a.Value.Any().(error); ok {
				errObj = e
			}
		}

		if a.Key == "event" || a.Key == "Event" {
			eventObj = a.Value.String()
		}
		return true
	})

	errMsg := ""
	if errObj != nil {
		errMsg = errObj.Error()
	}

	h.logChan <- types.LogEvent{
		Message: r.Message,
		TestId:  h.testId,
		Level:   r.Level,
		Error:   errMsg,
		Event:   eventObj,
	}

	return nil
}

func (h *LogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return h
}
func (h *LogHandler) WithGroup(name string) slog.Handler {
	return h
}
