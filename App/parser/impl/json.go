package impl

import (
	"Engine-AntiGinx/App/Errors"
	helpers "Engine-AntiGinx/App/Helpers"
	"Engine-AntiGinx/App/parser/config/types"
	"fmt"
)

// JsonParser reads configuration from a JSON file.
type JsonParser struct {
	fileReader helpers.FileReader
}

// CreateJsonParser initializes and returns a new instance of JsonParser.
func CreateJsonParser(fileReader helpers.FileReader) *JsonParser {
	return &JsonParser{
		fileReader: fileReader,
	}
}

// Parse reads, validates and converts file parameters.
func (j *JsonParser) Parse(userParameters []string) []*types.CommandParameter {
	length := len(userParameters)
	if length < 3 {
		message := `Json parser error occurred. This could be due to:
				- insufficient number of parameters`
		j.throwPanic(100, message)
	}
	fileName := userParameters[2]

	testJson := j.deserializeWithErrorHandling(fileName)

	if testJson.Target == "" || testJson.Parameters == nil || len(testJson.Parameters) == 0 {
		message := `Json parser error occurred. This could be due to:
				- empty target
				- not given or empty parameters`
		j.throwPanic(101, message)
	}

	target := testJson.Target
	params := testJson.Parameters

	finalList := append([]*types.CommandParameter{
		{
			Name:      "--target",
			Arguments: []string{target},
		}}, params...)
	err := helpers.CheckParameters(params)
	if err != nil {
		j.throwPanic(err.Code, err.Message)
	}

	return finalList
}

// deserializeWithErrorHandling reads and deserializes a JSON file.
func (j *JsonParser) deserializeWithErrorHandling(fileName string) *types.TestJson {
	// Empty file name case
	if fileName == "" {
		message := `Json parser error occurred. This could be due to:
				- empty file name`
		j.throwPanic(102, message)
	}

	file, err := j.fileReader.ReadFileW(fileName)
	// Opening file error case
	if err != nil {
		message := fmt.Sprintf("Json parser error occurred. This could be due to: \n"+
			"- %v", err)
		j.throwPanic(103, message)
	}
	if len(file) == 0 {
		message := fmt.Sprintf("Json parser error occurred. This could be due to: \n" +
			"- empty file")
		j.throwPanic(104, message)
	}
	tests, err2 := helpers.DeserializeTests(file)
	if err2 != nil {
		j.throwPanic(err2.Code, err2.Message)
	}
	return tests
}

// throwPanic reports a parser error.
func (j *JsonParser) throwPanic(code int, message string) {
	panic(Errors.Error{
		Code:        code,
		Message:     message,
		Source:      "json parser",
		IsRetryable: false,
	},
	)
}
