package impl

import (
	types2 "Engine-AntiGinx/App/parser/config/types"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHelpParser_Parse(t *testing.T) {
	tests := []types2.CliParserTest{
		{
			Name:    "Happy path, general help",
			Params:  []string{"scanner", "help"},
			WantErr: false,
			Want:    []*types2.CommandParameter{},
		},
		{
			Name:    "Happy path, specific command help",
			Params:  []string{"scanner", "help", "--tests"},
			WantErr: false,
			Want: []*types2.CommandParameter{
				{
					Name:      "--tests",
					Arguments: nil,
				},
			},
		},
		{
			Name:    "Invalid help command passed",
			Params:  []string{"scanner", "help", "invalid"},
			WantErr: true,
			Want:    nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			defer func() {
				r := recover()
				if r != nil {
					if !tt.WantErr {
						t.Errorf("Unexpected panic: %v", r)
					}
				} else {
					if tt.WantErr {
						t.Errorf("Expected panic but got none")
					}
				}
			}()
			hParser := CreateHelpParser()

			params := hParser.Parse(tt.Params)
			if !tt.WantErr {
				assert.Equal(t, tt.Want, params, "Parsed parameters are not exactly the same.")
			}

		})
	}
}
