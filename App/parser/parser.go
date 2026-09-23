package parser

import (
	"Engine-AntiGinx/App/parser/config/types"
)

// Parser converts input arguments into command parameters.
type Parser interface {
// Parse returns parameters or panics on invalid input.
	Parse(userParameters []string) []*types.CommandParameter
}
