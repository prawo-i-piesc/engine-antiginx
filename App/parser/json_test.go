package parser

import (
	"Engine-AntiGinx/App/Errors"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

type MockReader struct {
	dataToReturn []byte
	errToReturn  error
}

func (m *MockReader) ReadFileW(filename string) ([]byte, error) {
	return m.dataToReturn, m.errToReturn
}

func TestJsonParser_Parse(t *testing.T) {
	tests := []jsonParserTest{
		{
			name:        "Happy path",
			params:      []string{"scanner", "json", "happyJson.json"},
			wantErrCode: 0,
			want: []*CommandParameter{
				{Name: "--target", Arguments: []string{"Target"}},
				{Name: "--tests", Arguments: []string{"https", "csp"}},
				{Name: "--antiBotDetection", Arguments: []string{""}},
			},
			fileName:    "happy.json",
			errToReturn: nil,
		},

		// File reader error
		{
			name:         "File reader error",
			params:       []string{"scanner", "json", "spookyFile.json"},
			wantErrCode:  103,
			want:         nil,
			dataToReturn: []byte(`{"Target": "MyServer","Parameters": []}`),
			errToReturn:  errors.New("file reader error"),
		},

		//	Invalid Json File cases
		{
			name:         "Empty json file",
			params:       []string{"scanner", "json", "empty.json"},
			wantErrCode:  104,
			want:         nil,
			dataToReturn: []byte{},
			errToReturn:  nil,
		},
		{
			name:        "Syntax error",
			params:      []string{"scanner", "json", "syntaxErr.json"},
			wantErrCode: 105,
			want:        nil,
			fileName:    "invalidjson.json",
			errToReturn: nil,
		},

		// Invalid test configuration
		{
			name:        "Nil param case",
			params:      []string{"scanner", "json", "nilParam.json"},
			wantErrCode: 200,
			want:        nil,
			fileName:    "nilparam.json",
			errToReturn: nil,
		},
		{
			name:        "Repetitive params",
			params:      []string{"scanner", "json", "repetitiveParam.json"},
			wantErrCode: 202,
			want:        nil,
			fileName:    "repetitiveParam.json",
			errToReturn: nil,
		},
		{
			name:        "Empty args list",
			params:      []string{"scanner", "json", "emptyArgs.json"},
			wantErrCode: 203,
			want:        nil,
			fileName:    "emptyArgs.json",
			errToReturn: nil,
		},
		{
			name:        "Invalid param",
			params:      []string{"scanner", "json", "invalid.json"},
			wantErrCode: 201,
			want:        nil,
			fileName:    "invalidParam.json",
			errToReturn: nil,
		},
		{
			name:        "Too few args",
			params:      []string{"scanner", "json", "tooFew.json"},
			wantErrCode: 203,
			want:        nil,
			fileName:    "tooFewArgs.json",
			errToReturn: nil,
		},
		{
			name:        "Too many args",
			params:      []string{"scanner", "json", "tooMany.json"},
			wantErrCode: 204,
			want:        nil,
			fileName:    "tooManyArgs.json",
			errToReturn: nil,
		},
		{
			name:         "Absent filename",
			params:       []string{"scanner", "json"},
			wantErrCode:  100,
			want:         nil,
			dataToReturn: nil,
			errToReturn:  nil,
		},
		{
			name:         "Empty filename",
			params:       []string{"scanner", "json", ""},
			wantErrCode:  102,
			want:         nil,
			dataToReturn: nil,
			errToReturn:  nil,
		},
		{
			name:        "Empty target",
			params:      []string{"scanner", "json", "emptyT.json"},
			wantErrCode: 101,
			want:        nil,
			fileName:    "emptyTarget.json",
			errToReturn: nil,
		},
		{
			name:        "Repetitive arg",
			params:      []string{"scanner", "json", "repArg.json"},
			wantErrCode: 206,
			want:        nil,
			fileName:    "repetitiveArgs.json",
			errToReturn: nil,
		},
		{
			name:        "Invalid arg",
			params:      []string{"scanner", "json", "repArg.json"},
			wantErrCode: 205,
			want:        nil,
			fileName:    "invalidArg.json",
			errToReturn: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var inputData []byte

			if tt.fileName != "" {
				inputData = loadFixture(t, tt.fileName)
			} else {
				inputData = tt.dataToReturn
			}
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
			mockReader := &MockReader{
				dataToReturn: inputData,
				errToReturn:  tt.errToReturn,
			}
			parser := CreateJsonParser(mockReader)
			got := parser.Parse(tt.params)

			if tt.wantErrCode == 0 {
				assert.Equal(t, tt.want, got)
			}
		})
	}
}
func loadFixture(t *testing.T, filename string) []byte {
	t.Helper()
	path := filepath.Join("testdata", filename)
	bytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to load fixture %s: %v", filename, err)
	}
	return bytes
}
