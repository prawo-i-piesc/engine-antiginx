package impl

import (
	"Engine-AntiGinx/App/Errors"
	types2 "Engine-AntiGinx/App/parser/config/types"
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
	tests := []types2.JsonParserTest{
		{
			Name:        "Happy path",
			Params:      []string{"scanner", "json", "happyJson.json"},
			WantErrCode: 0,
			Want: []*types2.CommandParameter{
				{Name: "--target", Arguments: []string{"Target"}},
				{Name: "--tests", Arguments: []string{"https", "csp"}},
				{Name: "--antiBotDetection", Arguments: []string{""}},
			},
			FileName:    "happy.json",
			ErrToReturn: nil,
		},

		// File reader error
		{
			Name:         "File reader error",
			Params:       []string{"scanner", "json", "spookyFile.json"},
			WantErrCode:  103,
			Want:         nil,
			DataToReturn: []byte(`{"Target": "MyServer","Parameters": []}`),
			ErrToReturn:  errors.New("file reader error"),
		},

		//	Invalid Json File cases
		{
			Name:         "Empty json file",
			Params:       []string{"scanner", "json", "empty.json"},
			WantErrCode:  104,
			Want:         nil,
			DataToReturn: []byte{},
			ErrToReturn:  nil,
		},

		// Invalid test configuration
		{
			Name:         "Absent filename",
			Params:       []string{"scanner", "json"},
			WantErrCode:  100,
			Want:         nil,
			DataToReturn: nil,
			ErrToReturn:  nil,
		},
		{
			Name:         "Empty filename",
			Params:       []string{"scanner", "json", ""},
			WantErrCode:  102,
			Want:         nil,
			DataToReturn: nil,
			ErrToReturn:  nil,
		},
		{
			Name:        "Empty target",
			Params:      []string{"scanner", "json", "emptyT.json"},
			WantErrCode: 101,
			Want:        nil,
			FileName:    "emptyTarget.json",
			ErrToReturn: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			var inputData []byte

			if tt.FileName != "" {
				inputData = loadFixture(t, tt.FileName)
			} else {
				inputData = tt.DataToReturn
			}
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
			mockReader := &MockReader{
				dataToReturn: inputData,
				errToReturn:  tt.ErrToReturn,
			}
			parser := CreateJsonParser(mockReader)
			got := parser.Parse(tt.Params)

			if tt.WantErrCode == 0 {
				assert.Equal(t, tt.Want, got)
			}
		})
	}
}
func loadFixture(t *testing.T, filename string) []byte {
	t.Helper()
	path := filepath.Join("../testdata", filename)
	bytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to load fixture %s: %v", filename, err)
	}
	return bytes
}
