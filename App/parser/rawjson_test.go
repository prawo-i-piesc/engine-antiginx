package parser

import (
	"Engine-AntiGinx/App/Errors"
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRawJsonParser_Parse(t *testing.T) {
	tests := []jsonParserTest{
		{
			name:        "Happy Path",
			params:      []string{},
			wantErrCode: 0,
			want: []*CommandParameter{
				{Name: "--target", Arguments: []string{"Target"}},
				{Name: "--tests", Arguments: []string{"https", "csp"}},
				{Name: "--antiBotDetection", Arguments: []string{""}},
			},
			fileName: "happy.json",
		},
		{
			name:        "Empty Target",
			params:      []string{},
			wantErrCode: 101,
			fileName:    "emptyTarget.json",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inputBytes := loadBytes(t, tt.fileName)
			mockStdin := bytes.NewReader(inputBytes)

			defer func() {
				r := recover()
				if tt.wantErrCode != 0 {
					if r == nil {
						t.Errorf("Expected error with code %d, program ended with 0", tt.wantErrCode)
					}
					err, ok := r.(Errors.Error)

					if !ok {
						t.Errorf("Unexpected error type %v", r)
					} else if err.Code != tt.wantErrCode {
						t.Errorf("Expected error with code %d, ended with %d", tt.wantErrCode, err.Code)
					}
				} else {
					if r != nil {
						t.Errorf("Unexpected panic %v", r)
					}
				}
				return
			}()

			rawParser := CreateRawJsonParser(mockStdin)
			got := rawParser.Parse(tt.params)
			if tt.wantErrCode == 0 {
				assert.Equal(t, tt.want, got)
			}
		})
	}
}
func loadBytes(t *testing.T, filename string) []byte {
	t.Helper()
	path := filepath.Join("testdata", filename)
	testBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to load fixture %s: %v", filename, err)
	}
	return testBytes
}
