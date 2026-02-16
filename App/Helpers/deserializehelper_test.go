package helpers

import (
	"Engine-AntiGinx/App/parser/config/types"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestCheckParameters(t *testing.T) {
	tests := []types.DesHelpTest{
		{
			Name:       "Happy path",
			ExpErrCode: 0,
			Filename:   "happyDes.json",
		},
		{
			Name:       "Nil param case",
			ExpErrCode: 101,
			Filename:   "nilparam.json",
		},
		{
			Name:       "Repetitive params",
			ExpErrCode: 103,
			Filename:   "repetitiveParam.json",
		},
		{
			Name:       "Empty args",
			ExpErrCode: 104,
			Filename:   "emptyArgs.json",
		},
		{
			Name:       "Invalid param",
			ExpErrCode: 102,
			Filename:   "invalidParam.json",
		},
		{
			Name:       "Too few args",
			ExpErrCode: 104,
			Filename:   "tooFewArgs.json",
		},
		{
			Name:       "Too many args",
			ExpErrCode: 105,
			Filename:   "tooManyArgs.json",
		},
		{
			Name:       "Repetitive arg",
			ExpErrCode: 107,
			Filename:   "repetitiveArgs.json",
		},
		{
			Name:       "Invalid arg",
			ExpErrCode: 106,
			Filename:   "invalidArg.json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			givenData := loadJsonParams(t, tt.Filename)
			err := CheckParameters(givenData)
			if err != nil {
				if tt.ExpErrCode == 0 {
					t.Errorf("Unexpected error,\nmessage: %s\ncode: %d ", err.Message, err.Code)
				} else if tt.ExpErrCode != err.Code {
					t.Errorf("Expected error with code %d got %d ", tt.ExpErrCode, err.Code)
				}
			} else {
				if tt.ExpErrCode != 0 {
					t.Errorf("Expected error with code %d got none", tt.ExpErrCode)
				}
			}
		})
	}
}

func loadJsonParams(t *testing.T, filename string) []*types.CommandParameter {
	t.Helper()
	path := filepath.Join("../parser/testdata", filename)
	bytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to load fixture %s: %v", filename, err)
	}
	var commands []*types.CommandParameter
	err2 := json.Unmarshal(bytes, &commands)
	if err2 != nil {
		t.Fatalf("Failed to load fixture %s: %v", filename, err2)
	}
	return commands
}
