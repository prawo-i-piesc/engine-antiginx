package execution

import (
	"Engine-AntiGinx/App/execution/strategy"
	"bytes"
	"log/slog"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

type mockTestStrategy struct {
	name string
}

func (m mockTestStrategy) GetName() string { return m.name }
func (m mockTestStrategy) Execute(ctx strategy.TestContext, channel chan strategy.ResultWrapper, wg *sync.WaitGroup, antiBotFlag bool) {
}
func (m mockTestStrategy) GetPreferredReporterType() strategy.ReporterType {
	return strategy.CLIReporter
}

func TestPlan_LogPlan(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	originalLogger := slog.Default()
	slog.SetDefault(slog.New(handler))

	defer slog.SetDefault(originalLogger)

	t.Run("LogPlan in Help mode", func(t *testing.T) {
		buf.Reset()
		plan := &Plan{
			IsHelp: true,
			Strategies: []strategy.TestStrategy{
				mockTestStrategy{name: "help_strat"},
			},
		}

		plan.LogPlan()
		output := buf.String()

		assert.Contains(t, output, "Execution plan constructed for Help mode")
		assert.Contains(t, output, `"strategiesCount":1`)
		assert.NotContains(t, output, "target")
	})

	t.Run("LogPlan in Standard mode", func(t *testing.T) {
		buf.Reset()
		plan := &Plan{
			Target:      "https://example.com",
			AntiBotFlag: true,
			TaskId:      "task-999",
			IsHelp:      false,
			Strategies: []strategy.TestStrategy{
				mockTestStrategy{name: "strat_A"},
				mockTestStrategy{name: "strat_B"},
			},
			Contexts: map[string]strategy.TestContext{
				"strat_A": {},
			},
		}

		plan.LogPlan()
		output := buf.String()

		assert.Contains(t, output, "Execution plan constructed")
		assert.Contains(t, output, `"target":"https://example.com"`)
		assert.Contains(t, output, `"antiBotFlag":true`)
		assert.Contains(t, output, `"taskId":"task-999"`)
		assert.Contains(t, output, `"strategies":["strat_A","strat_B"]`)
		assert.Contains(t, output, `"contextsCount":1`)
	})
}
