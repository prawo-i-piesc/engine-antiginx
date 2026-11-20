package Reporter

import (
	"Engine-AntiGinx/App/Reporter/types"
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewLogHandler(t *testing.T) {
	logChan := make(chan types.LogEvent)
	handler := NewLogHandler(logChan, "task-123", slog.LevelDebug)

	assert.NotNil(t, handler)
	assert.Equal(t, "task-123", handler.testId)
	assert.Equal(t, slog.LevelDebug, handler.level)
	assert.Equal(t, (chan<- types.LogEvent)(logChan), handler.logChan)
}

func TestLogHandler_Enabled(t *testing.T) {
	handler := &LogHandler{level: slog.LevelInfo}
	ctx := context.Background()

	assert.False(t, handler.Enabled(ctx, slog.LevelDebug))
	assert.True(t, handler.Enabled(ctx, slog.LevelInfo))
	assert.True(t, handler.Enabled(ctx, slog.LevelWarn))
	assert.True(t, handler.Enabled(ctx, slog.LevelError))
}

func TestLogHandler_Handle(t *testing.T) {
	logChan := make(chan types.LogEvent, 2)
	handler := &LogHandler{
		logChan: logChan,
		testId:  "task-123",
		level:   slog.LevelInfo,
	}
	ctx := context.Background()

	t.Run("Handle with error and event attributes", func(t *testing.T) {
		record := slog.NewRecord(time.Now(), slog.LevelError, "test message", 0)
		record.AddAttrs(
			slog.Any("error", errors.New("test error")),
			slog.String("event", "TEST_EVENT"),
			slog.String("other", "ignored"),
		)

		err := handler.Handle(ctx, record)
		assert.NoError(t, err)

		event := <-logChan
		assert.Equal(t, "test message", event.Message)
		assert.Equal(t, "task-123", event.TestId)
		assert.Equal(t, slog.LevelError, event.Level)
		assert.Equal(t, "test error", event.Error)
		assert.Equal(t, "TEST_EVENT", event.Event)
	})

	t.Run("Handle without error attribute", func(t *testing.T) {
		record := slog.NewRecord(time.Now(), slog.LevelInfo, "clean message", 0)

		err := handler.Handle(ctx, record)
		assert.NoError(t, err)

		event := <-logChan
		assert.Equal(t, "clean message", event.Message)
		assert.Equal(t, "", event.Error)
		assert.Equal(t, "", event.Event)
	})
}

func TestLogHandler_WithAttrs_WithGroup(t *testing.T) {
	handler := &LogHandler{}

	assert.Equal(t, handler, handler.WithAttrs([]slog.Attr{slog.String("k", "v")}))
	assert.Equal(t, handler, handler.WithGroup("test_group"))
}
