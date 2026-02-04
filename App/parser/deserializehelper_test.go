package parser

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestCheckParameters(t *testing.T) {
	tests := []desHelpTest{
		{
			name:       "Happy path",
			expErrCode: 0,
			filename:   "happyDes.json",
		},
		{
			name:       "Nil param case",
			expErrCode: 101,
			filename:   "nilparam.json",
		},
		{
			name:       "Repetitive params",
			expErrCode: 103,
			filename:   "repetitiveParam.json",
		},
		{
			name:       "Empty args",
			expErrCode: 104,
			filename:   "emptyArgs.json",
		},
		{
			name:       "Invalid param",
			expErrCode: 102,
			filename:   "invalidParam.json",
		},
		{
			name:       "Too few args",
			expErrCode: 104,
			filename:   "tooFewArgs.json",
		},
		{
			name:       "Too many args",
			expErrCode: 105,
			filename:   "tooManyArgs.json",
		},
		{
			name:       "Repetitive arg",
			expErrCode: 107,
			filename:   "repetitiveArgs.json",
		},
		{
			name:       "Invalid arg",
			expErrCode: 106,
			filename:   "invalidArg.json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			givenData := loadJsonParams(t, tt.filename)
			err := CheckParameters(givenData)
			if err != nil {
				if tt.expErrCode == 0 {
					t.Errorf("Unexpected error,\nmessage: %s\ncode: %d ", err.Message, err.Code)
				} else if tt.expErrCode != err.Code {
					t.Errorf("Expected error with code %d got %d ", tt.expErrCode, err.Code)
				}
			} else {
				if tt.expErrCode != 0 {
					t.Errorf("Expected error with code %d got none", tt.expErrCode)
				}
			}
		})
	}
}

func loadJsonParams(t *testing.T, filename string) []*CommandParameter {
	t.Helper()
	path := filepath.Join("testdata", filename)
	bytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to load fixture %s: %v", filename, err)
	}
	var commands []*CommandParameter
	err2 := json.Unmarshal(bytes, &commands)
	if err2 != nil {
		t.Fatalf("Failed to load fixture %s: %v", filename, err2)
	}
	return commands
}
