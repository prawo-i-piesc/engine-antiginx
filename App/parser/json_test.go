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

		// Invalid test configuration
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
