package execution

import (
	"Engine-AntiGinx/App/execution/strategy"
	"log/slog"
)

// Plan represents a complete blueprint for a security scanning task.
type Plan struct {
	Target      string
	AntiBotFlag bool
	Strategies  []strategy.TestStrategy
	Contexts    map[string]strategy.TestContext
	TaskId      string
	IsHelp      bool
}

func (p *Plan) LogPlan() {
	if p.IsHelp {
		slog.Debug("Execution plan constructed for Help mode", slog.Int("strategiesCount", len(p.Strategies)))
		return
	}

	strategyNames := make([]string, 0, len(p.Strategies))
	for _, strat := range p.Strategies {
		strategyNames = append(strategyNames, strat.GetName())
	}

	slog.Debug("Execution plan constructed",
		slog.String("target", p.Target),
		slog.Bool("antiBotFlag", p.AntiBotFlag),
		slog.String("taskId", p.TaskId),
		slog.Any("strategies", strategyNames),
		slog.Int("contextsCount", len(p.Contexts)))
}
