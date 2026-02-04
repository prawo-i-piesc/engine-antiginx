package parser

import (
	"Engine-AntiGinx/App/Errors"
	"fmt"
)

// JsonParser is responsible for reading
// configuration logic from a JSON file
// and error handling.
// Logic of deserialization and validation
// moved to deserialize helper
type JsonParser struct {
	fileReader FileReader
}

// CreateJsonParser initializes and returns a new instance of JsonParser.
func CreateJsonParser(fileReader FileReader) *JsonParser {
	return &JsonParser{
		fileReader: fileReader,
	}
}

// Parse orchestrates the parsing process. It expects userParameters to contain
// the filename at index 2. It reads the file, validates parameters against
// defined rules, and returns a consolidated list of CommandParameter objects.
//
// It prepends the target as a "--target" parameter to the final list.
// This method panics if validation fails or the file cannot be read.
func (j *JsonParser) Parse(userParameters []string) []*CommandParameter {
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

	finalList := append([]*CommandParameter{
		{
			Name:      "--target",
			Arguments: []string{target},
		}}, params...)
	err := CheckParameters(params)
	if err != nil {
		j.throwPanic(err.Code, err.Message)
	}

	return finalList
}

// deserializeWithErrorHandling reads the file from the disk and unmarshalls it into a TestJson struct.
// It handles file I/O errors and JSON syntax errors by triggering a panic with a descriptive message.
func (j *JsonParser) deserializeWithErrorHandling(fileName string) *TestJson {
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
	tests, err2 := DeserializeTests(file)
	if err2 != nil {
		j.throwPanic(err2.Code, err2.Message)
	}
	return tests
}

// throwPanic is a helper method to construct and panic with a standard application Error.
// This is used to interrupt the control flow when a validation or parsing error occurs.
func (j *JsonParser) throwPanic(code int, message string) {
	panic(Errors.Error{
		Code:        code,
		Message:     message,
		Source:      "json parser",
		IsRetryable: false,
	},
	)
}
