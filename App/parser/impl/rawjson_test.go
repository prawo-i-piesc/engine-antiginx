package impl

import (
	"Engine-AntiGinx/App/Errors"
	types2 "Engine-AntiGinx/App/parser/config/types"
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRawJsonParser_Parse(t *testing.T) {
	tests := []types2.JsonParserTest{
		{
			Name:        "Happy Path",
			Params:      []string{},
			WantErrCode: 0,
			Want: []*types2.CommandParameter{
				{Name: "--target", Arguments: []string{"Target"}},
				{Name: "--tests", Arguments: []string{"https", "csp"}},
				{Name: "--antiBotDetection", Arguments: []string{""}},
			},
			FileName: "happy.json",
		},
		{
			Name:        "Empty Target",
			Params:      []string{},
			WantErrCode: 101,
			FileName:    "emptyTarget.json",
		},
	}
	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			inputBytes := loadBytes(t, tt.FileName)
			mockStdin := bytes.NewReader(inputBytes)

			defer func() {
				r := recover()
				if tt.WantErrCode != 0 {
					if r == nil {
						t.Errorf("Expected error with code %d, program ended with 0", tt.WantErrCode)
					}
					err, ok := r.(Errors.Error)

					if !ok {
						t.Errorf("Unexpected error type %v", r)
					} else if err.Code != tt.WantErrCode {
						t.Errorf("Expected error with code %d, ended with %d", tt.WantErrCode, err.Code)
					}
				} else {
					if r != nil {
						t.Errorf("Unexpected panic %v", r)
					}
				}
				return
			}()

			rawParser := CreateRawJsonParser(mockStdin)
			got := rawParser.Parse(tt.Params)
			if tt.WantErrCode == 0 {
				assert.Equal(t, tt.Want, got)
			}
		})
	}
}
func loadBytes(t *testing.T, filename string) []byte {
	t.Helper()
	path := filepath.Join("../testdata", filename)
	testBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to load fixture %s: %v", filename, err)
	}
	return testBytes
}
