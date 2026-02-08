package execution

import "Engine-AntiGinx/App/parser/config/types"

type Formatter interface {
	FormatParameters(params []*types.CommandParameter) *Plan
}
